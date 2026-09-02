"""Operational metrics for the database tier (roadmap Phase 6, DB-09/DB-12).

``/api/health`` says the process is up and ``/api/ready`` says it can serve.
Neither answers the operator's next question: *is this installation heading for
trouble?* That needs the signals below, and each one is here because its
absence is a way this product fails silently:

- **Pool saturation** — requests queuing for a connection is the first symptom
  of a scale problem, and it is invisible from response codes until it is not.
- **Database and artifact size, plus disk headroom** — the estate grows with
  every scan; running the volume out of space corrupts nothing but stops
  everything.
- **Backup age** — a backup that quietly stopped is only discovered during a
  recovery, which is the worst possible time.
- **WAL archive lag and failures** — point-in-time recovery is a promise made
  by a background process nobody watches.
- **Long-running transactions and lock waits** — the usual cause of a "the app
  is hung" report, and the thing a migration blocks behind.
- **Replication lag** — reports as absent (rather than zero) while this host
  has no standby, so the gap stays visible instead of looking healthy.

Every collector is individually guarded: a metrics endpoint that fails because
one optional signal is unavailable is worse than one that reports the rest and
names what it could not read. Nothing here is tenant data, and nothing here is
a credential.
"""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

# A statement running longer than this is worth an operator's attention. It is
# not an error - long analytical reads exist - but it is the shape of a problem.
LONG_TRANSACTION_SECONDS = 60.0


def _safe(collector, name: str, into: dict, unavailable: list[str]) -> None:
    try:
        into[name] = collector()
    except Exception as exc:  # pragma: no cover - optional signal guard
        unavailable.append(f"{name}: {type(exc).__name__}")


def pool_metrics() -> dict:
    """Connection pool saturation (PostgreSQL only; SQLite does not pool)."""
    from backend import db

    if not db.is_postgres():
        return {"backend": "sqlite", "pooled": False}
    pool = db._get_pool()
    if pool is None:
        return {"backend": "postgres", "pooled": False, "reason": "psycopg_pool absent"}
    stats = pool.get_stats()
    # pool_size is how many connections currently EXIST, not the ceiling. The
    # pool opens lazily, so a one-connection pool serving one caller is 100%
    # of its current size and ~10% of its capacity - measuring against
    # max_size is what makes saturation mean "close to refusing work".
    size = int(stats.get("pool_size", 0) or 0)
    available = int(stats.get("pool_available", 0) or 0)
    capacity = int(getattr(pool, "max_size", 0) or size or 1)
    in_use = max(0, size - available)
    return {
        "backend": "postgres",
        "pooled": True,
        "capacity": capacity,
        "size": size,
        "available": available,
        "in_use": in_use,
        "waiting": int(stats.get("requests_waiting", 0) or 0),
        "requests_queued": int(stats.get("requests_queued", 0) or 0),
        "requests_errors": int(stats.get("connections_errors", 0) or 0),
        # Saturation is the number operators should alert on, not raw counts.
        "utilization": round(in_use / capacity, 3) if capacity else 0.0,
    }


def storage_metrics() -> dict:
    """Database size, artifact store size, and headroom on their volume."""
    from backend import artifacts, db

    result: dict = {}
    if db.is_postgres():
        with db.connect(Path("unused")) as conn:
            row = conn.execute(
                "SELECT pg_database_size(current_database()) AS bytes"
            ).fetchone()
        result["database_bytes"] = int(row["bytes"])
    else:
        from backend.store import DB_PATH

        path = Path(DB_PATH)
        result["database_bytes"] = path.stat().st_size if path.exists() else 0

    stats = artifacts.store_stats()
    result["artifact_objects"] = stats["objects"]
    result["artifact_bytes"] = stats["ciphertext_bytes"]

    # Headroom on the volume that actually holds the data directory.
    target = Path(os.getenv("DSPM_DATA_DIR", "data")).resolve()
    probe = target if target.exists() else Path.cwd()
    usage = shutil.disk_usage(probe)
    result["disk_total_bytes"] = usage.total
    result["disk_free_bytes"] = usage.free
    result["disk_free_ratio"] = round(usage.free / usage.total, 4) if usage.total else 0.0
    return result


def backup_metrics() -> dict:
    from backend import backup

    age = backup.latest_backup_age_seconds()
    manifests = backup.list_manifests()
    return {
        "sets_retained": len(manifests),
        "age_seconds": round(age, 1) if age is not None else None,
        "max_age_hours": float(os.getenv("DSPM_BACKUP_MAX_AGE_HOURS", "26")),
    }


def wal_metrics() -> dict:
    """WAL archiving health - the mechanism point-in-time recovery rests on."""
    from backend import db

    if not db.is_postgres():
        return {"applicable": False}
    with db.connect(Path("unused")) as conn:
        row = conn.execute(
            "SELECT archived_count, failed_count, "
            "EXTRACT(EPOCH FROM (now() - last_archived_time)) AS since_archive, "
            "EXTRACT(EPOCH FROM (now() - last_failed_time)) AS since_failure "
            "FROM pg_stat_archiver"
        ).fetchone()
        mode = conn.execute("SHOW archive_mode").fetchone()
    since = row["since_archive"]
    return {
        "applicable": True,
        "archive_mode": str(mode["archive_mode"]),
        "archived_count": int(row["archived_count"] or 0),
        "failed_count": int(row["failed_count"] or 0),
        "seconds_since_last_archive": round(float(since), 1) if since is not None else None,
        "seconds_since_last_failure": (
            round(float(row["since_failure"]), 1) if row["since_failure"] is not None else None
        ),
    }


def replication_metrics() -> dict:
    """Standby lag. Reported as configured=False rather than as zero lag while
    no standby exists, so an absent standby cannot read as a healthy one."""
    from backend import db

    if not db.is_postgres():
        return {"applicable": False}
    with db.connect(Path("unused")) as conn:
        rows = conn.execute(
            "SELECT application_name, state, "
            "EXTRACT(EPOCH FROM COALESCE(replay_lag, '0 seconds'::interval)) AS lag "
            "FROM pg_stat_replication"
        ).fetchall()
    return {
        "applicable": True,
        "configured": bool(rows),
        "standbys": [
            {
                "name": str(r["application_name"] or ""),
                "state": str(r["state"] or ""),
                "replay_lag_seconds": round(float(r["lag"] or 0), 3),
            }
            for r in rows
        ],
    }


def activity_metrics() -> dict:
    """Long-running transactions and lock waits."""
    from backend import db

    if not db.is_postgres():
        return {"applicable": False}
    with db.connect(Path("unused")) as conn:
        long_running = conn.execute(
            "SELECT COUNT(*) AS n FROM pg_stat_activity "
            "WHERE state <> 'idle' AND xact_start IS NOT NULL "
            "AND now() - xact_start > make_interval(secs => ?)",
            (LONG_TRANSACTION_SECONDS,),
        ).fetchone()
        blocked = conn.execute(
            "SELECT COUNT(*) AS n FROM pg_locks WHERE NOT granted"
        ).fetchone()
        connections = conn.execute(
            "SELECT COUNT(*) AS n FROM pg_stat_activity WHERE datname = current_database()"
        ).fetchone()
    return {
        "applicable": True,
        "connections": int(connections["n"]),
        "long_running_transactions": int(long_running["n"]),
        "long_transaction_threshold_seconds": LONG_TRANSACTION_SECONDS,
        "waiting_locks": int(blocked["n"]),
    }


def schema_metrics() -> dict:
    from backend import migrations, store

    with store._connect() as conn:
        applied = migrations.current_revision(conn)
    return {"applied": applied, "expected": migrations.expected_revision()}


def collect() -> dict:
    """Gather every metric family. Individually guarded; never raises."""
    started = time.perf_counter()
    metrics: dict = {}
    unavailable: list[str] = []
    for name, collector in (
        ("pool", pool_metrics),
        ("storage", storage_metrics),
        ("backup", backup_metrics),
        ("wal_archive", wal_metrics),
        ("replication", replication_metrics),
        ("activity", activity_metrics),
        ("schema_revision", schema_metrics),
    ):
        _safe(collector, name, metrics, unavailable)
    metrics["unavailable"] = unavailable
    metrics["collection_seconds"] = round(time.perf_counter() - started, 3)
    metrics["warnings"] = _warnings(metrics)
    return metrics


def _warnings(metrics: dict) -> list[str]:
    """Turn raw numbers into the handful of statements worth acting on."""
    out: list[str] = []

    # Only judge a signal that was actually collected. A family missing from
    # the payload means its collector failed - which `unavailable` already
    # reports - and "no backup manifest found" would be a different, false
    # claim about the installation.
    if "backup" in metrics:
        backup_block = metrics["backup"] or {}
        age = backup_block.get("age_seconds")
        max_age = float(backup_block.get("max_age_hours") or 26) * 3600
        if age is None:
            out.append("no backup manifest found")
        elif age > max_age:
            out.append(f"newest backup is {age / 3600:.1f}h old")

    storage = metrics.get("storage") or {}
    free_ratio = storage.get("disk_free_ratio")
    if free_ratio is not None and free_ratio < 0.10:
        out.append(f"disk free is {free_ratio * 100:.1f}% of the volume")

    pool = metrics.get("pool") or {}
    if pool.get("pooled") and float(pool.get("utilization") or 0) >= 0.9:
        out.append(f"connection pool {float(pool['utilization']) * 100:.0f}% utilized")
    if int(pool.get("waiting") or 0) > 0:
        out.append(f"{pool['waiting']} request(s) waiting for a connection")

    wal = metrics.get("wal_archive") or {}
    if wal.get("applicable"):
        if str(wal.get("archive_mode")) != "on":
            out.append("WAL archiving is off - point-in-time recovery is not available")
        if int(wal.get("failed_count") or 0) > 0:
            out.append(f"WAL archiver has {wal['failed_count']} failure(s)")

    activity = metrics.get("activity") or {}
    if int(activity.get("long_running_transactions") or 0) > 0:
        out.append(f"{activity['long_running_transactions']} transaction(s) running over "
                   f"{activity.get('long_transaction_threshold_seconds')}s")
    if int(activity.get("waiting_locks") or 0) > 0:
        out.append(f"{activity['waiting_locks']} lock request(s) waiting")

    replication = metrics.get("replication") or {}
    if replication.get("applicable") and not replication.get("configured"):
        out.append("no streaming standby is connected (single-host deployment)")

    revision = metrics.get("schema_revision") or {}
    if revision.get("applied") != revision.get("expected"):
        out.append(f"schema revision {revision.get('applied')} != expected {revision.get('expected')}")
    return out


def slow_queries(limit: int = 20) -> dict:
    """Top statements by total execution time, from pg_stat_statements.

    Query text is treated as sensitive: pg_stat_statements normalizes literals
    into placeholders, but identifiers and structure still describe the estate,
    so this is admin-only and never enters logs or health payloads.
    """
    from backend import db

    if not db.is_postgres():
        return {"available": False, "reason": "PostgreSQL only"}
    limit = max(1, min(int(limit or 20), 100))
    with db.connect(Path("unused")) as conn:
        installed = conn.execute(
            "SELECT COUNT(*) AS n FROM pg_extension WHERE extname = 'pg_stat_statements'"
        ).fetchone()
        if not int(installed["n"]):
            return {
                "available": False,
                "reason": "pg_stat_statements is not installed on this database",
            }
        rows = conn.execute(
            "SELECT query, calls, "
            "round(total_exec_time::numeric, 1) AS total_ms, "
            "round(mean_exec_time::numeric, 2) AS mean_ms, "
            "round(max_exec_time::numeric, 2) AS max_ms, rows "
            "FROM pg_stat_statements "
            "WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database()) "
            "ORDER BY total_exec_time DESC LIMIT ?",
            (limit,),
        ).fetchall()
    threshold = float(os.getenv("DSPM_SLOW_QUERY_MEAN_MS", "250"))
    statements = []
    redacted = 0
    for row in rows:
        text = " ".join(str(row["query"] or "").split())
        # PostgreSQL replaces the text with this marker for roles that lack
        # pg_read_all_stats. The timings are still true and still actionable,
        # so report them and say the text is redacted rather than surfacing a
        # column full of "<insufficient privilege>".
        if text == "<insufficient privilege>":
            redacted += 1
            text = ""
        statements.append({
            "query": text[:400],
            "calls": int(row["calls"] or 0),
            "total_ms": float(row["total_ms"] or 0),
            "mean_ms": float(row["mean_ms"] or 0),
            "max_ms": float(row["max_ms"] or 0),
            "rows": int(row["rows"] or 0),
        })
    result = {
        "available": True,
        "review_threshold_mean_ms": threshold,
        "over_threshold": sum(1 for s in statements if s["mean_ms"] > threshold),
        "query_text_visible": redacted == 0,
        "statements": statements,
    }
    if redacted:
        # Deliberately not fixed by granting the runtime role pg_read_all_stats:
        # that would let the application role read every other role's activity,
        # which is a real privilege increase for a cosmetic gain.
        result["note"] = (
            f"{redacted} statement text(s) redacted by PostgreSQL: the runtime role "
            "lacks pg_read_all_stats. Timings above are accurate. To see query text, "
            "connect as sentro_readonly (which holds pg_read_all_stats) rather than "
            "widening the application role."
        )
    return result
