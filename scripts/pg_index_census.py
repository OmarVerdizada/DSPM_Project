"""Which index answers which read, on PostgreSQL (scaling roadmap W4.1 step 5: "every survivor
is justified by a read").

    python scripts/pg_index_census.py [--files 10000] [--drop NAME[,NAME...]] [--json OUT]

On the disposable sentro_test database only. It fills a tenant with a varied synthetic
estate - sources, risk levels, extensions, labels, protection, owners, finding types, triage -
ANALYZEs, and runs what the console reads and what a rescan writes: an inventory page for
every sort in both directions, with each filter and its second page; the facets; the
remediation list for every sort and each filter; the remediation summary; the dashboard's
inputs; an asset's and a finding's drawer; a baseline probe; an unchanged and a changed save
of one label. Every statement that touches assets, findings, finding_index,
scan_object_baselines or asset_access is EXPLAINed before it runs. It prints, per index on
those tables, the statements whose plans use it, and every statement a hot table answered by
reading it whole.

``--drop`` drops the named indexes first and puts them back, from their own definitions,
at the end: the same workload then shows what answers those statements without them.
``--no-seqscan`` EXPLAINs with sequential scans disabled (the statements themselves run as
usual): at this size the planner rightly reads a small table whole for a sorted page, and
this shows the index that answers the read once it is not small. The tenant is erased at
the end.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
import uuid
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

HOT_TABLES = ("assets", "findings", "finding_index", "scan_object_baselines", "asset_access")
SOURCES = ("smb", "local", "endpoint-winrm")
LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
EXTENSIONS = (".xlsx", ".docx", ".pdf", ".txt", ".csv", ".zip")
TYPES = ("email", "phone", "iban", "credit_card", "passport_number", "aws_access_key", "national_id")
FRAMEWORKS = ("gdpr", "pci_dss", "hipaa", "nist")
LABELS = 5
# Measured (pg_write_bench, W2.1-W3.5): well under 64 KB of WAL a file on a first save.
WAL_BYTES_PER_FILE_ESTIMATE = 64 * 1024


def _report(scan_id: str, label: int, start: int, count: int, stamp: str, *, incremental: bool) -> dict:
    files = []
    for index in range(start, start + count):
        source = SOURCES[index % len(SOURCES)]
        level = LEVELS[index % len(LEVELS)]
        findings = [{
            "finding_id": f"c-{index}-{k}", "type": TYPES[(index + k) % len(TYPES)], "risk": level,
            "framework": FRAMEWORKS[(index + k) % len(FRAMEWORKS)], "count": 1 + k, "status": "OPEN",
            "confidence": 60 + (index % 40), "owner": f"owner{index % 13}",
        } for k in range(index % 4)]
        extension = EXTENSIONS[index % len(EXTENSIONS)]
        name = f"file_{index:07d}{extension}"
        files.append({
            "path": f"//fs{label:02d}/share{index % 7}/dept{index % 41:02d}/{name}", "name": name,
            "extension": extension, "size": 1_000 + (index * 7919) % 5_000_000, "owner": f"CORP\\user{index % 29}",
            "modified_at": f"2026-0{1 + index % 9}-{1 + index % 28:02d}T00:00:00+00:00", "source": source,
            "share": f"share{index % 7}", "content_hash": f"{index:064x}", "content_status": "scanned",
            "protected": index % 17 == 0, "risk": {"level": level, "score": 100 - LEVELS.index(level) * 25 - index % 20},
            "findings": findings,
        })
    report = {"scan_id": scan_id, "source": SOURCES[label % len(SOURCES)], "scan_label": f"label-{label}",
              "summary": {"total_files": count}, "timestamp": stamp, "files": files}
    if incremental:
        report["scan_diagnostics"] = {"incremental": {"enabled": True, "baseline_update": True,
                                                      "scope_key": f"census-{label}", "version_signature": "v1",
                                                      "complete": True}}
    return report


class Census:
    """Every statement on a hot table EXPLAINed, keyed by its text."""

    def __init__(self, no_seqscan: bool = False) -> None:
        self.no_seqscan = no_seqscan
        self.plans: dict[str, dict] = {}
        self.uses: dict[str, set[str]] = defaultdict(set)
        self.whole: dict[str, set[str]] = defaultdict(set)
        self.step = ""

    def install(self, db) -> None:
        real = db._PgConn.execute
        census = self

        def execute(conn, sql, params=()):
            text = " ".join(str(sql).split())
            head = text.split(" ", 1)[0].upper()
            if head in {"SELECT", "WITH", "UPDATE", "DELETE"} and any(f" {t} " in f" {text} " or f" {t}(" in text
                                                                    for t in HOT_TABLES):
                census.explain(conn, sql, params, text)
            return real(conn, sql, params)

        db._PgConn.execute = execute

    def explain(self, conn, sql, params, text: str) -> None:
        from backend.db import translate_sql

        key = hashlib.sha256(text.encode()).hexdigest()[:12]
        try:
            if self.no_seqscan:
                conn._raw.execute("SET enable_seqscan = off")
            try:
                row = conn._raw.execute("EXPLAIN (FORMAT JSON) " + translate_sql(sql), tuple(params)).fetchone()
            finally:
                if self.no_seqscan:
                    conn._raw.execute("RESET enable_seqscan")
        except Exception as exc:  # noqa: BLE001 - a statement EXPLAIN cannot take is reported, not fatal
            self.plans.setdefault(key, {"sql": text[:220], "steps": set(), "error": type(exc).__name__})
            return
        plan = row[0][0]["Plan"] if not isinstance(row[0], str) else json.loads(row[0])[0]["Plan"]
        indexes, whole = set(), set()

        def walk(node: dict) -> None:
            if node.get("Index Name"):
                indexes.add(str(node["Index Name"]))
            if node.get("Node Type") == "Seq Scan" and node.get("Relation Name") in HOT_TABLES:
                whole.add(str(node["Relation Name"]))
            for child in node.get("Plans") or []:
                walk(child)

        walk(plan)
        entry = self.plans.setdefault(key, {"sql": text[:220], "steps": set(), "indexes": set(), "whole": set(),
                                            "cost": 0.0})
        entry["steps"].add(self.step)
        entry["indexes"] |= indexes
        entry["whole"] |= whole
        entry["cost"] = max(float(entry.get("cost") or 0.0), float(plan.get("Total Cost") or 0.0))
        for name in indexes:
            self.uses[name].add(key)


def _index_definitions(store, names: list[str]) -> dict[str, str]:
    with store._connect() as conn:
        return {str(row["indexname"]): str(row["indexdef"]) for row in conn.execute(
            "SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = current_schema() AND indexname = ANY(?)",
            (names,)).fetchall()}


def _all_indexes(store) -> dict[str, str]:
    with store._connect() as conn:
        return {str(row["indexname"]): str(row["tablename"]) for row in conn.execute(
            "SELECT indexname, tablename FROM pg_indexes WHERE schemaname = current_schema() AND tablename = ANY(?)",
            (list(HOT_TABLES),)).fetchall()}


def _erase_one_asset(store, tenant: str) -> None:
    """What erasure and the demo purge run per asset: its rows found by the asset id."""
    from backend import db

    with db.tenant_scope(tenant), store._connect() as conn:
        asset = conn.execute("SELECT id FROM assets WHERE tenant_id = ? AND finding_count > 0 LIMIT 1",
                             (tenant,)).fetchone()
        for table in ("asset_access", "findings"):
            conn.execute(f"DELETE FROM {table} WHERE asset_id = ? AND tenant_id = ?",  # noqa: S608 - fixed names
                         (str(asset["id"]), tenant))
        conn.execute("DELETE FROM assets WHERE id = ? AND tenant_id = ?", (str(asset["id"]), tenant))


def workload(store, census: Census, tenant: str, files: int) -> None:
    from backend import db

    def step(name: str, fn, *args, **kwargs):
        census.step = name
        started = time.perf_counter()
        result = fn(*args, **kwargs)
        census.timings[name] = round((time.perf_counter() - started) * 1000, 1)
        return result

    census.timings = {}
    for sort in store.INVENTORY_SORTS:
        for direction in ("ASC", "DESC"):
            page = step(f"inventory {sort} {direction}", store.list_inventory, tenant, sort=sort, direction=direction,
                        limit=50)
            if page.get("next_cursor"):
                step(f"inventory {sort} {direction} page 2", store.list_inventory, tenant, sort=sort,
                     direction=direction, cursor=page["next_cursor"], limit=50)
    for name, filters in (("risk", {"risk": "HIGH"}), ("source", {"source": "smb"}),
                          ("extension", {"extension": ".pdf"}), ("protected", {"protected": True}),
                          ("unprotected", {"protected": False}), ("framework", {"framework": "pci_dss"}),
                          ("finding type", {"finding_type": "iban"}), ("search", {"q": "dept07"}),
                          ("risk+source", {"risk": "CRITICAL", "source": "local"}),
                          ("risk+source+extension", {"risk": "MEDIUM", "source": "smb", "extension": ".docx"})):
        for sort in ("risk_score", "modified_at", "name"):
            page = step(f"inventory {name} by {sort}", store.list_inventory, tenant, sort=sort, limit=50, **filters)
            if page.get("next_cursor"):
                step(f"inventory {name} by {sort} page 2", store.list_inventory, tenant, sort=sort,
                     cursor=page["next_cursor"], limit=50, **filters)
    step("facets", store.inventory_facets, tenant)
    step("facets smb", store.inventory_facets, tenant, source="smb")
    for sort in store.REMEDIATION_SORTS:
        for direction in ("ASC", "DESC"):
            page = step(f"remediation {sort} {direction}", store.list_remediation_findings, tenant, sort=sort,
                        direction=direction, limit=50)
            after = page.get("next_cursor") or page.get("next_after") or ""
            if after:
                step(f"remediation {sort} {direction} page 2", store.list_remediation_findings, tenant, sort=sort,
                     direction=direction, after=after, limit=50)
    for name, filters in (("status", {"status": "CONFIRMED"}), ("severity", {"severity": "CRITICAL"}),
                          ("owner", {"owner": "owner3"}), ("framework", {"framework": "hipaa"}),
                          ("data type", {"data_type": "iban"}), ("sla", {"sla": "overdue"}),
                          ("search", {"q": "file_00012"}), ("scope all", {"scope": "all"})):
        step(f"remediation {name}", store.list_remediation_findings, tenant, limit=50, **filters)
    step("remediation summary", store.remediation_summary, tenant)
    step("findings list", store.list_findings, tenant)
    with db.tenant_scope(tenant), store._connect() as conn:
        conn.execute("DELETE FROM derived_cache WHERE tenant_id = ?", (tenant,))
    step("posture inputs", store.posture_inputs, tenant)
    step("retention summary", store.data_retention_summary, tenant)
    step("scan history", store.read_scan_history, tenant, limit=14)
    with db.tenant_scope(tenant), store._connect() as conn:
        asset = conn.execute("SELECT id, path FROM assets WHERE tenant_id = ? AND finding_count > 0 LIMIT 1",
                             (tenant,)).fetchone()
        finding = conn.execute("SELECT id FROM findings WHERE tenant_id = ? AND is_current = 1 LIMIT 1",
                               (tenant,)).fetchone()
        principal = conn.execute("SELECT principal_key FROM asset_access WHERE tenant_id = ? LIMIT 1",
                                 (tenant,)).fetchone()
    step("asset drawer", store.get_inventory_asset, tenant, str(asset["id"]))
    step("finding drawer", store.get_finding, tenant, str(finding["id"]))
    step("finding history", store.get_finding_history, tenant, str(finding["id"]))
    step("access principals", store.list_access_principals, tenant)
    if principal is not None:
        step("access assets", store.list_access_assets, tenant, principal_key=str(principal["principal_key"]))
    step("baseline probe", store.probe_incremental_object, tenant, "census-0", str(asset["path"]), 0, "", "v1")

    # A rescan of one label: unchanged, then with some files' findings changed.
    per_label = files // LABELS
    unchanged = _report("census-r1", 0, 0, per_label, "2026-10-08T01:00:00+00:00", incremental=True)
    step("rescan save, unchanged", store.save_scan_history, tenant, unchanged)
    changed = _report("census-r2", 0, 0, per_label, "2026-10-08T02:00:00+00:00", incremental=True)
    for record in changed["files"][::10]:
        record["findings"] = record["findings"][1:]
        record["content_hash"] = "f" * 64
    step("rescan save, 10% changed", store.save_scan_history, tenant, changed)
    # ... and one that no longer sees a tenth of the label: a complete scan prunes those assets
    # and retires their findings.
    shrunk = _report("census-r3", 0, 0, per_label, "2026-10-08T03:00:00+00:00", incremental=True)
    shrunk["files"] = shrunk["files"][: per_label - per_label // 10]
    step("rescan save, 10% gone", store.save_scan_history, tenant, shrunk)
    step("erase one asset", _erase_one_asset, store, tenant)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--files", type=int, default=10_000)
    parser.add_argument("--drop", default="", help="comma-separated index names to drop for the run")
    parser.add_argument("--json", default="", help="write the census as JSON here")
    parser.add_argument("--no-seqscan", action="store_true", help="EXPLAIN with sequential scans disabled")
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
              "(WAL in pg_wal and the archive). Free space or pass --force.", file=sys.stderr)
        return 3

    from backend import db, store

    tenant = f"census-{uuid.uuid4().hex[:6]}"
    store.create_tenant(tenant, "index census")
    dropped = [name for name in args.drop.split(",") if name.strip()]
    definitions = _index_definitions(store, dropped) if dropped else {}
    missing = sorted(set(dropped) - set(definitions))
    if missing:
        print(f"refusing: no such index: {', '.join(missing)}", file=sys.stderr)
        return 4
    census = Census(no_seqscan=args.no_seqscan)
    try:
        started = time.perf_counter()
        per_label = args.files // LABELS
        for label in range(LABELS):
            store.save_scan_history(tenant, _report(f"census-{label}", label, label * per_label, per_label,
                                                    f"2026-10-0{1 + label}T00:00:00+00:00", incremental=label == 0))
        with db.tenant_scope(tenant), store._connect() as conn:
            ids = [str(row["id"]) for row in conn.execute(
                "SELECT id FROM findings WHERE tenant_id = ? AND is_current = 1 ORDER BY id LIMIT 400",
                (tenant,)).fetchall()]
        for position, finding_id in enumerate(ids):
            action = ("status", {"status": "CONFIRMED"}) if position % 2 else ("assign", {"owner": "hr-team"})
            store.update_finding_lifecycle(tenant, finding_id, action[0], action[1], "census")
        with store._connect() as conn:
            for table in HOT_TABLES:
                conn.execute(f"ANALYZE {table}")  # noqa: S608 - fixed names
            for name in dropped:
                conn.execute(f"DROP INDEX IF EXISTS {name}")  # noqa: S608 - names checked against pg_indexes
        print(f"estate of {args.files} files in {time.perf_counter() - started:.0f} s; dropped: {dropped or 'none'}",
              flush=True)
        census.install(db)
        workload(store, census, tenant, args.files)
    finally:
        with store._connect() as conn:
            for name, definition in definitions.items():
                conn.execute(definition.replace("CREATE INDEX ", "CREATE INDEX IF NOT EXISTS ", 1))
        store.delete_tenant_with_data(tenant)

    indexes = _all_indexes(store)
    print("\nindex                                                         table          statements")
    for name in sorted(indexes, key=lambda item: (indexes[item], item)):
        steps = sorted({step for key in census.uses.get(name, ()) for step in census.plans[key]["steps"]})
        print(f"{name:<62}{indexes[name]:<15}{len(census.uses.get(name, ())):>4}  {'; '.join(steps)[:150]}")
    print("\nstatements reading a hot table whole:")
    for key, entry in census.plans.items():
        if entry.get("whole"):
            print(f"  {sorted(entry['whole'])} cost {entry['cost']:.0f} <- {sorted(entry['steps'])[:3]}: "
                  f"{entry['sql'][:140]}")
    errors = [entry for entry in census.plans.values() if entry.get("error")]
    if errors:
        print(f"\n{len(errors)} statements EXPLAIN could not take (e.g. {errors[0]['sql'][:100]})")
    if args.json:
        Path(args.json).write_text(json.dumps({
            "files": args.files, "dropped": dropped, "no_seqscan": args.no_seqscan, "timings_ms": census.timings,
            "plans": {key: {**entry, "steps": sorted(entry["steps"]), "indexes": sorted(entry.get("indexes") or ()),
                            "whole": sorted(entry.get("whole") or ())} for key, entry in census.plans.items()},
        }, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
