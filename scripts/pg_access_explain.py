"""EXPLAIN (ANALYZE, BUFFERS) of every query the access pages issue, on a synthetic tenant.

    python scripts/pg_access_explain.py --files 10000 [--keep] [--out DIR]

Writes a tenant of ``--files`` files straight into PostgreSQL (``DSPM_DB_URL``, which must be
a disposable database: sentro_test), each with the access rows a typical Windows estate
holds - SYSTEM and Administrators full control and BUILTIN\\Users read (inherited) on every
file, an owner, Everyone read on 2% of files, Domain Users write on 0.1%, an unresolved SID
on 0.5% - 10% of the files sensitive. Then it calls the store's own access functions and
EXPLAINs exactly the statements they issued (recorded, not copied), plus the aggregate the
principals page ran before revision 0055, and reports for each its execution time and the
rows it read. The question it answers: does any access page read every access row of the
tenant? What grows with the estate is said per statement (rows read), so a larger estate's
cost can be EXTRAPOLATED from it.

Refuses to run unless free disk on the database's drive stays above the floor afterwards
(the WAL of the seed is written twice: pg_wal and the archive).
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

DISK_FLOOR_MIB = 2048
# MEASURED on sentro_test: about 3.6 KiB of WAL a synthetic file (its asset row, ~4 access
# rows and their indexes, the count deltas), written twice (pg_wal and the archive).
WAL_KIB_PER_FILE = 4


def _old_principals_sql() -> str:
    """The principals aggregate before revision 0055 (D7), for the before/after."""
    return ("SELECT aa.principal_key AS principal_key, MAX(aa.principal) AS principal, MAX(aa.sid) AS sid, "
            "MAX(aa.broad) AS broad, MAX(aa.privileged) AS privileged, MAX(aa.service) AS service, "
            "SUM(aa.can_read) AS readable, SUM(aa.can_write) AS writable, "
            "SUM(CASE WHEN aa.can_read = 1 AND a.finding_count > 0 THEN 1 ELSE 0 END) AS readable_sensitive, "
            "MAX(CASE WHEN aa.can_read = 1 THEN a.risk_score ELSE 0 END) AS max_risk_score "
            "FROM asset_access aa JOIN assets a ON a.tenant_id = aa.tenant_id AND a.id = aa.asset_id "
            "WHERE aa.tenant_id = ? GROUP BY aa.principal_key "
            "ORDER BY readable_sensitive DESC, readable DESC, aa.principal_key LIMIT ?")


def _seed(conn, tenant: str, files: int) -> None:
    conn.execute(
        "INSERT INTO assets (tenant_id, id, source, stable_object_id, path, name, extension, share, risk_level, "
        "risk_score, size, owner, modified_at, finding_count, detail_json, scan_label, current_scan_id, acl_state) "
        "SELECT ?, 'acx' || g, 'smb', 'obj' || g, '\\\\fs01\\data\\dept' || (g % 40) || '\\file' || g || '.txt', "
        "'file' || g || '.txt', '.txt', 'data', CASE WHEN g % 10 = 0 THEN 'HIGH' ELSE 'NONE' END, "
        "CASE WHEN g % 10 = 0 THEN 40 + (g % 50) ELSE 0 END, 1000, 'CORP\\u' || (g % 500), '2026-10-01', "
        "CASE WHEN g % 10 = 0 THEN 2 ELSE 0 END, '{}', 'explain', 'scan-explain', 'collected' "
        "FROM generate_series(1, ?) AS g", (tenant, files))
    principals = [
        # key, name, type, rights, allow, can_read, can_write, modify, full, broad, privileged, service,
        # unresolved, explicit, inherited, owner, every
        ("S-1-5-18", "NT AUTHORITY\\SYSTEM", "service", "Full control", 0x1F01FF, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1),
        ("S-1-5-32-544", "BUILTIN\\Administrators", "group", "Full control", 0x1F01FF, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1),
        ("S-1-5-32-545", "BUILTIN\\Users", "group", "Read & execute", 0x1200A9, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1),
        ("S-1-1-0", "Everyone", "well_known_group", "Read", 0x120089, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 50),
        ("S-1-5-21-1-2-3-513", "CORP\\Domain Users", "group", "Modify", 0x1301BF, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1000),
        ("S-1-5-21-9-9-9-1234", "S-1-5-21-9-9-9-1234", "unresolved_sid", "Read", 0x120089, 1, 0, 0, 0, 0, 0, 0, 1, 0,
         1, 0, 200),
    ]
    columns = ("tenant_id, asset_id, principal_key, principal, sid, principal_type, rights, allow_mask, deny_mask, "
               "explicit_mask, can_read, can_write, can_modify, full_control, change_perms, has_deny, has_explicit, "
               "has_inherited, is_owner, broad, privileged, service, unresolved, sensitive, risk_score, scan_id")
    for key, name, kind, rights, allow, read, write, modify, full, broad, privileged, service, unresolved, explicit, \
            inherited, _owner, every in principals:
        conn.execute(
            f"INSERT INTO asset_access ({columns}) SELECT ?, 'acx' || g, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, 0, ?, ?, "
            "0, ?, ?, ?, ?, CASE WHEN g % 10 = 0 THEN 1 ELSE 0 END, CASE WHEN g % 10 = 0 THEN 40 + (g % 50) ELSE 0 END, "
            "'scan-explain' FROM generate_series(1, ?) AS g WHERE g % ? = 0",
            (tenant, key, name, key, kind, rights, allow, allow if explicit else 0, read, write, modify, full,
             full, explicit, inherited, broad, privileged, service, unresolved, files, every))
    # Each file's owner: one of 500 users, full control by an explicit entry.
    conn.execute(
        f"INSERT INTO asset_access ({columns}) SELECT ?, 'acx' || g, 'S-1-5-21-1-2-3-' || (1000 + g % 500), "
        "'CORP\\u' || (g % 500), 'S-1-5-21-1-2-3-' || (1000 + g % 500), 'user', 'Full control', 2032127, 0, 2032127, "
        "1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, CASE WHEN g % 10 = 0 THEN 1 ELSE 0 END, "
        "CASE WHEN g % 10 = 0 THEN 40 + (g % 50) ELSE 0 END, 'scan-explain' FROM generate_series(1, ?) AS g",
        (tenant, files))
    conn.execute(
        "INSERT INTO asset_acl_changes (tenant_id, id, asset_id, scan_id, detected_at, path, severity, sensitive, "
        "broad_exposure, change_count, summary) SELECT ?, 'chg' || g, 'acx' || g, 'scan-explain', "
        "'2026-10-10T00:00:' || lpad((g % 60)::text, 2, '0'), 'p' || g, 'medium', 1, 1, 1, 'Everyone: gained read' "
        "FROM generate_series(1, 200) AS g", (tenant,))


class _Recorder:
    def __init__(self, conn, sink: list) -> None:
        self._conn = conn
        self._sink = sink

    def execute(self, sql, params=()):
        self._sink.append((str(sql), tuple(params or ())))
        return self._conn.execute(sql, params)

    def __getattr__(self, name):
        return getattr(self._conn, name)


def _explain(store, sql: str, params: tuple) -> dict:
    with store._connect() as conn:
        lines = [str(next(iter(dict(row).values()))) if hasattr(row, "keys") else str(row[0])
                 for row in conn.execute("EXPLAIN (ANALYZE, BUFFERS) " + sql, params).fetchall()]
    text = "\n".join(lines)
    execution = re.search(r"Execution Time: ([0-9.]+) ms", text)
    reads = [int(float(match)) for match in re.findall(r"actual time=[0-9.]+\.\.[0-9.]+ rows=([0-9.]+)", text)]
    seq = [line.strip() for line in lines if "Seq Scan" in line]
    return {"execution_ms": float(execution.group(1)) if execution else None, "max_node_rows": max(reads or [0]),
            "seq_scans": seq, "plan": text}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--files", type=int, default=10000)
    parser.add_argument("--keep", action="store_true", help="leave the synthetic tenant in the database")
    parser.add_argument("--out", default="")
    args = parser.parse_args()
    url = os.getenv("DSPM_DB_URL", "")
    if "sentro_test" not in url:
        print("refusing: DSPM_DB_URL must name the disposable sentro_test database", file=sys.stderr)
        return 2
    free_mib = shutil.disk_usage("C:\\").free // (1024 * 1024)
    need_mib = 2 * args.files * WAL_KIB_PER_FILE // 1024 + 40
    if free_mib - need_mib < DISK_FLOOR_MIB:
        print(f"refusing: {free_mib} MiB free, the seed needs about {need_mib} MiB and the floor is "
              f"{DISK_FLOOR_MIB} MiB", file=sys.stderr)
        return 3
    from backend import db, estate_counts, store

    tenant = f"acx-{os.getpid()}"
    store.create_tenant(tenant, "access explain")
    results: dict = {"files": args.files, "tenant": tenant}
    try:
        started = time.perf_counter()
        with db.tenant_scope(tenant), store._connect() as conn:
            _seed(conn, tenant, args.files)
        with db.tenant_scope(tenant), store._connect() as conn:
            estate_counts.fold(conn, tenant)
            rows = conn.execute("SELECT COUNT(*) AS n FROM asset_access WHERE tenant_id = ?", (tenant,)).fetchone()
        results["access_rows"] = int(rows["n"])
        results["seed_seconds"] = round(time.perf_counter() - started, 1)
        with db.tenant_scope(tenant), store._connect() as conn:
            conn.execute("ANALYZE asset_access")
            conn.execute("ANALYZE assets")
            conn.execute("ANALYZE estate_counts")

        cases = {
            "principals (counts)": lambda: store.list_access_principals(tenant, limit=200),
            "principals kind=broad (counts)": lambda: store.list_access_principals(tenant, kind="broad"),
            "files Users, sensitive (rank index)": lambda: store.list_access_assets(
                tenant, principal_key="S-1-5-32-545", sensitive_only=True, limit=100),
            "files Users, all (rank index)": lambda: store.list_access_assets(
                tenant, principal_key="S-1-5-32-545", sensitive_only=False, limit=100),
            "files Everyone, write (none exist)": lambda: store.list_access_assets(
                tenant, principal_key="S-1-1-0", access="write", sensitive_only=False, limit=100),
            "files kind=broad, write (broad-write index)": lambda: store.list_access_assets(
                tenant, kind="broad", access="write", sensitive_only=False, limit=100),
            "files owned by one user": lambda: store.list_access_assets(
                tenant, principal_key="S-1-5-21-1-2-3-1007", access="owner", sensitive_only=False, limit=100),
            "file detail": lambda: store.get_asset_access(tenant, "acx10"),
            "changes, newest first": lambda: store.list_acl_changes(tenant, limit=50),
            "summary (counts)": lambda: store.access_summary(tenant),
        }
        report: dict = {}
        real_connect = store._connect
        for name, call in cases.items():
            recorded: list = []

            @contextlib.contextmanager
            def recording(*a, _sink=recorded, **k):
                with real_connect(*a, **k) as conn:
                    yield _Recorder(conn, _sink)

            store._connect = recording
            try:
                with db.tenant_scope(tenant):
                    call()
            finally:
                store._connect = real_connect
            with db.tenant_scope(tenant):
                explained = [_explain(store, sql, params) for sql, params in recorded if sql.lstrip().upper().startswith(
                    ("SELECT", "WITH"))]
            report[name] = {"statements": len(explained),
                            "execution_ms": round(sum(item["execution_ms"] or 0 for item in explained), 2),
                            "max_rows_any_node": max((item["max_node_rows"] for item in explained), default=0),
                            "seq_scans": [scan for item in explained for scan in item["seq_scans"]],
                            "plans": [item["plan"] for item in explained]}
        with db.tenant_scope(tenant):
            for name, sql, params in (
                    ("principals BEFORE revision 0055 (aggregate over every access row)", _old_principals_sql(),
                     (tenant, 200)),
                    ("principals oracle (DSPM_MAINTAINED_COUNTS=0)", None, None)):
                if sql is None:
                    recorded = []

                    @contextlib.contextmanager
                    def recording(*a, _sink=recorded, **k):
                        with real_connect(*a, **k) as conn:
                            yield _Recorder(conn, _sink)

                    store._connect = recording
                    try:
                        store._build_access_principals(tenant, "", 200)
                    finally:
                        store._connect = real_connect
                    sql, params = recorded[0]
                explained = _explain(store, sql, params)
                report[name] = {"statements": 1, "execution_ms": explained["execution_ms"],
                                "max_rows_any_node": explained["max_node_rows"], "seq_scans": explained["seq_scans"],
                                "plans": [explained["plan"]]}
            # The broad-write rows without their index: what the partial index saves.
            with store._connect() as conn:
                conn.execute("DROP INDEX IF EXISTS idx_asset_access_broad_write")
                plan_sql = ("SELECT aa.asset_id FROM asset_access aa WHERE aa.tenant_id = ? AND aa.principal_key = ? "
                            "AND aa.broad = 1 AND aa.can_write = 1 ORDER BY aa.sensitive DESC, aa.risk_score DESC, "
                            "aa.asset_id ASC LIMIT 100")
                lines = [str(next(iter(dict(row).values())))
                         for row in conn.execute("EXPLAIN (ANALYZE, BUFFERS) " + plan_sql,
                                                 (tenant, "S-1-5-32-545")).fetchall()]
                conn._raw.rollback()  # the index stays: DROP INDEX is transactional
            text = "\n".join(lines)
            execution = re.search(r"Execution Time: ([0-9.]+) ms", text)
            report["broad write rows of Users WITHOUT the broad-write index"] = {
                "execution_ms": float(execution.group(1)) if execution else None,
                "max_rows_any_node": max([int(float(value)) for value in re.findall(r"actual time=[0-9.]+\.\.[0-9.]+ rows=([0-9.]+)", text)] or [0]),
                "plans": [text]}
        results["queries"] = report
    finally:
        if not args.keep:
            with db.platform_scope("migration"), store._connect() as conn:
                for table in ("asset_acl_changes", "asset_access", "assets", "estate_count_deltas", "estate_counts",
                              "estate_count_state"):
                    conn.execute(f"DELETE FROM {table} WHERE tenant_id = ?", (tenant,))  # noqa: S608 - fixed names
                conn.execute("DELETE FROM tenants WHERE tenant_id = ?", (tenant,))
    out = Path(args.out) if args.out else ROOT / "tmp"
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"pg_access_explain_{args.files}.json"
    path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"{args.files} files, {results.get('access_rows')} access rows (seeded in {results.get('seed_seconds')} s)")
    for name, item in results.get("queries", {}).items():
        seq = f"  SEQ SCAN: {item['seq_scans']}" if item.get("seq_scans") else ""
        print(f"  {name:62s} {item['execution_ms']!s:>9} ms  rows read (largest node) {item['max_rows_any_node']}"
              f"{seq}")
    print(f"plans: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
