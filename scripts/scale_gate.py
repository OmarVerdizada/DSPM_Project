"""Phase B scale gate: the envelopes B0-B7 were delivered against, measured on every run.

`perf_gate.py` defends how FAST the product is. This defends how it SCALES - the
properties Phase B exists for, each of which was measured once, written into
`docs/PLAN_memurai_operational_plane_2026-09.md`, and then had nothing standing between it
and a quiet regression:

- **B0** the estate write costs a fixed number of statements, not one per file;
- **B1/B2** a partitioned scan holds one partition at a time, and reports what one scan
  reports;
- **B3** a partition handed out again after its worker committed it runs nothing twice -
  the worker-kill gate, against the ledger queue the workers use;
- **B4** an endpoint scan's memory follows its batch budget, not the size of the profile;
- **B7** one value found by three detectors is one finding, and a record is not padded
  with what its parent already says.

Every bound here is either a RATIO (host-independent: a slow CI runner and a fast
workstation agree on it) or a marginal cost per file. Absolute numbers are reported for
tracking, never gated across hosts.

    python scripts/scale_gate.py [--files 400] [--quick] [--json]

Exit code 1 on any failed check. Uses throwaway databases and temporary directories, and
never touches operator data.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import sys
import tempfile
import time
import tracemalloc
import uuid
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MB = 1024 * 1024
# Files per partition for the memory check. Small enough that a modest corpus splits
# several ways, large enough that per-partition overhead does not dominate.
PARTITION_BUDGET = 50

# The corpus one file contributes, in the shape a real estate has: a few sensitive
# values among ordinary text.
_FILE_TEMPLATE = """Customer record {index}
name: Ana Mammadova
email: user{index}@example.com
card number: 4111 1111 1111 1111
notes: quarterly summary, nothing else of interest
"""


def _corpus(root: Path, files: int) -> None:
    r"""Write the corpus where the collector will actually read it.

    `is_skipped_scan_path` skips anything under `\appdata\`, which is where a session
    temp directory lives, so an estate written there scans as ZERO files - and every
    check downstream passes vacuously. §7.4 of the plan lost four probe runs to this;
    `corpus_check` below is the standing guard against it.
    """
    for index in range(files):
        folder = root / f"dept{index % 8}"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / f"file{index:04d}.txt").write_text(_FILE_TEMPLATE.format(index=index), encoding="utf-8")


def _check(name: str, gate: str, ok: bool, measured, bound, detail: str = "") -> dict:
    return {"name": name, "gate": gate, "ok": bool(ok), "measured": measured, "bound": bound, "detail": detail}


# --------------------------------------------------------------------------- B0


class _CountingConnection:
    """Counts what a write costs, without changing what it does."""

    def __init__(self, conn, counts: dict) -> None:
        self._conn = conn
        self._counts = counts

    def execute(self, *args, **kwargs):
        self._counts["execute"] += 1
        return self._conn.execute(*args, **kwargs)

    def executemany(self, statement, rows, *args, **kwargs):
        rows = list(rows)
        self._counts["executemany"] += 1
        self._counts["rows"] += len(rows)
        return self._conn.executemany(statement, rows, *args, **kwargs)

    def __getattr__(self, item):
        return getattr(self._conn, item)


@contextlib.contextmanager
def _counting_statements(store):
    counts = {"execute": 0, "executemany": 0, "rows": 0}
    original = store.db.connect

    @contextlib.contextmanager
    def wrapped(path):
        with original(path) as conn:
            yield _CountingConnection(conn, counts)

    store.db.connect = wrapped
    try:
        yield counts
    finally:
        store.db.connect = original


def _synthetic_report(scan_id: str, files: int) -> dict:
    return {
        "scan_id": scan_id,
        "timestamp": "2026-09-17T00:00:00+00:00",
        "source": "smb",
        "scan_label": "scale-gate",
        "summary": {"total_files": files, "critical": 0, "high": files, "medium": 0, "low": 0,
                    "sensitive_files": files},
        "files": [
            {
                "path": f"//fs01/share/file{index:05d}.txt",
                "name": f"file{index:05d}.txt",
                "extension": ".txt",
                "size": 2048,
                "source": "smb",
                "share": "share",
                "owner": "CORP/owner",
                "modified_at": "2026-09-01T00:00:00Z",
                "risk": {"level": "HIGH", "score": 70, "reasons": ["PAN"]},
                "findings": [{
                    "type": "credit_card",
                    "risk": "HIGH",
                    "count": 1,
                    "description": "PAN in an export",
                    "samples": ["411111******1111"],
                    "secure_value_fingerprints": [f"fp-{index}"],
                }],
            }
            for index in range(files)
        ],
    }


def write_path_check(store, files: int) -> dict:
    """B0: what one more file costs the estate write.

    The fixed cost of a save is not interesting and differs with the schema; what the
    gate defends is the SLOPE - before B0 it was 9.0 statements per file, which is the
    shape that makes a million-file scan impossible.
    """
    small, large = files, files * 4
    measured = {}
    for count in (small, large):
        tenant = f"t{uuid.uuid4().hex[:8]}"
        store.create_tenant(tenant, "scale-gate")
        with _counting_statements(store) as counts:
            store.save_scan_history(tenant, _synthetic_report(f"scan-{count}", count))
        measured[count] = counts["execute"]
    per_file = round((measured[large] - measured[small]) / max(large - small, 1), 5)
    return _check(
        "write path: statements per extra file",
        "B0 (§8 write-path gate)",
        per_file < 0.02,
        per_file,
        "< 0.02",
        f"{measured[small]} statements at {small} files, {measured[large]} at {large}",
    )


# ----------------------------------------------------------------------- B1/B2


def _scan_config(tenant: str, estate: Path, cache: Path, *, compliance: bool = False):
    from discovery.discovery_engine import ScanConfig

    return ScanConfig(
        tenant_id=tenant,
        local_path=str(estate),
        walk_local_path=True,
        persistent_cache_enabled=False,
        cache_dir=str(cache),
        incremental_enabled=False,
        max_workers=1,
        compliance_enabled=compliance,
        compliance_frameworks=["pci_dss", "gdpr"] if compliance else [],
    )


def _findings_by_type(report: dict) -> dict:
    tally: dict[str, int] = {}
    for file_obj in report.get("files") or []:
        for finding in file_obj.get("findings") or []:
            name = str(finding.get("type") or "")
            tally[name] = tally.get(name, 0) + 1
    return tally


def partition_checks(store, estate: Path, base: Path, files: int) -> list[dict]:
    """B1/B2: one partition at a time, and the same answer as one scan."""
    from backend import partitioned_scan
    from discovery.discovery_engine import DSPMDiscoveryEngine

    single_tenant = f"t{uuid.uuid4().hex[:8]}"
    store.create_tenant(single_tenant, "scale-gate single")
    config = _scan_config(single_tenant, estate, base / "cache-single")
    tracemalloc.start()
    tracemalloc.reset_peak()
    started = time.perf_counter()
    single_report = DSPMDiscoveryEngine(config).run().to_dict()
    single_report["scan_id"] = "single"
    store.save_scan_history(single_tenant, single_report)
    single_peak = tracemalloc.get_traced_memory()[1]
    single_seconds = round(time.perf_counter() - started, 2)
    tracemalloc.stop()

    part_tenant = f"t{uuid.uuid4().hex[:8]}"
    store.create_tenant(part_tenant, "scale-gate partitioned")
    part_config = _scan_config(part_tenant, estate, base / "cache-part")
    # A FIXED budget, not a fraction of the corpus: the claim is that memory follows the
    # partition size, so a larger estate at the same budget must hold the same, not more.
    # (A files//4 budget hid this - four partitions of a bigger corpus each held more.)
    budget = PARTITION_BUDGET
    tracemalloc.start()
    tracemalloc.reset_peak()
    started = time.perf_counter()
    compact = partitioned_scan.run_partitioned_scan(part_tenant, part_config, max_files=budget)
    part_peak = tracemalloc.get_traced_memory()[1]
    part_seconds = round(time.perf_counter() - started, 2)
    tracemalloc.stop()
    if compact is None:
        return [_check("partitioned scan runs", "B2 (§8 partition parity)", False, "not partitioned",
                       "a partitioned run", f"the planner did not split {files} files at {budget} per partition")]

    part_report = store.read_scan_report(part_tenant, compact["scan_id"]) or {}
    ratio = round(part_peak / max(single_peak, 1), 3)
    partitions = int(((part_report.get("scan_diagnostics") or {}).get("partitioned") or {}).get("partitions") or 0)

    # Below a few hundred files the engine's fixed cost - detector catalogs, pools, the
    # keyword catalogs - is most of the peak, and no ratio can tell a partitioned scan
    # from a single one. The check still runs and still reports its number there; it is
    # only GATED at a corpus where the records dominate. A bound that cannot discriminate
    # is worse than no bound: it passes whatever happens and reads as evidence.
    gated = files >= 300
    bound = 0.7
    same_files = len(part_report.get("files") or []) == len(single_report.get("files") or [])
    same_findings = _findings_by_type(part_report) == _findings_by_type(single_report)
    same_summary = (part_report.get("summary") or {}).get("sensitive_files") == \
        (single_report.get("summary") or {}).get("sensitive_files")

    return [
        _check(
            "the corpus was actually scanned",
            "every gate below it",
            len(single_report.get("files") or []) == files,
            len(single_report.get("files") or []),
            f"{files} files",
            "a corpus the collector skips scans as nothing, and every check passes vacuously",
        ),
        _check(
            "partitioned scan holds less than a single scan",
            "B1/B2 (§8 memory gate)",
            ratio <= bound if gated else True,
            ratio,
            f"<= {bound} of the single scan's peak" if gated
            else f"reported only: {files} files is too few to discriminate (gated from 300)",
            f"{single_peak // 1024} KB single vs {part_peak // 1024} KB across {partitions} partitions "
            f"({files} files, {budget} per partition; {single_seconds}s vs {part_seconds}s)",
        ),
        _check(
            "a partitioned scan reports what one scan reports",
            "B2.2 (§8 partition parity)",
            same_files and same_findings and same_summary,
            {"files": same_files, "findings": same_findings, "summary": same_summary},
            "identical",
            f"{len(single_report.get('files') or [])} files, {sum(_findings_by_type(single_report).values())} findings",
        ),
    ]


# --------------------------------------------------------------------------- B3


def worker_kill_check(store, estate: Path, base: Path) -> dict:
    """B3: a partition written but never acknowledged is delivered again, and runs nothing twice.

    The crash the queue contract is built around: the database commit happened, the
    acknowledgement did not, so the message comes back. The ledger's claim is a
    compare-and-set on the unit's status, so the redelivery finds it done - and the estate
    is exactly what the first run left.
    """
    from backend import partitioned_scan

    tenant = f"t{uuid.uuid4().hex[:8]}"
    store.create_tenant(tenant, "scale-gate worker kill")
    config = _scan_config(tenant, estate, base / "cache-kill")
    record = partitioned_scan.start_partitioned_scan(
        tenant, config, request={"local_path": str(estate)}, scan_label="scale-gate", max_files=40,
    )
    if record is None:
        return _check("a crashed worker's partition runs once", "B3 (§8 worker kill)", False,
                      "not partitioned", "a partitioned run", "the planner did not split the corpus")

    units = store.list_scan_partitions(tenant, record["scan_id"])
    partition_id = units[0]["partition_id"]
    first = partitioned_scan.run_queued_partition(record, config, partition_id, worker_id="worker-a")
    after_first = _estate_fingerprint(store, tenant)
    # The same message, delivered again to another worker.
    second = partitioned_scan.run_queued_partition(record, config, partition_id, worker_id="worker-b")
    after_redelivery = _estate_fingerprint(store, tenant)

    ok = first == "written" and second == "finished" and after_first == after_redelivery
    return _check(
        "a partition redelivered after a crash runs nothing twice",
        "B3 (§8 worker kill)",
        ok,
        {"first": first, "redelivery": second, "estate_unchanged": after_first == after_redelivery},
        "written, then finished, with the estate unchanged",
        f"{len(units)} partitions; fingerprint {after_first[:12]}",
    )


def _estate_fingerprint(store, tenant: str) -> str:
    digest = hashlib.sha256()
    with store._connect() as conn:
        # A partition's records live on its ledger row, not in a table of their own.
        for table in ("assets", "findings", "finding_occurrences", "finding_index", "scan_partitions"):
            try:
                rows = conn.execute(f"SELECT * FROM {table} WHERE tenant_id = ?", (tenant,)).fetchall()
            except Exception:
                continue
            for row in sorted(json.dumps([str(value) for value in tuple(item)]) for item in rows):
                digest.update(row.encode("utf-8"))
    return digest.hexdigest()


# --------------------------------------------------------------------------- B4


def endpoint_paging_check(files: int, file_bytes: int = MB) -> dict:
    """B4: what an endpoint scan holds follows its batch budget, not the size of the scope."""

    from backend.app import EndpointScanRequest, _run_endpoint_scan_payload
    from backend.security import Principal
    from collectors.winrm_endpoint_scanner import WinRMEndpointConfig

    paths = [rf"C:\Users\ana\Documents\file-{index}.txt" for index in range(files)]
    metadata = [{"source": "endpoint-winrm", "share": "endpoint-01", "path": path,
                 "name": path.rsplit("\\", 1)[-1], "size": file_bytes, "extension": ".txt",
                 "modified_at": "2026-08-28T00:00:00Z", "content": "", "sha256": "a" * 64}
                for path in paths]

    class Scanner:
        def __init__(self, config):
            self.config = config
            self.last_scan_diagnostics: dict = {}
            self.last_connection_host = "endpoint-01"

        def scan(self):
            if not self.config.read_content:
                return metadata
            return [{**item, "content": "x" * file_bytes}
                    for item in metadata if item["path"] in set(self.config.paths)]

    def analyze(_report, records, _job=None, **_bounds):
        return [{key: value for key, value in record.items() if key != "content"} for record in records]

    class Report:
        def __init__(self) -> None:
            self.last_scan_diagnostics: dict = {}

        def _finalize_incremental_diagnostics(self, analyzed) -> None:
            self.last_scan_diagnostics["incremental"] = {"complete": True, "total_objects": len(analyzed)}

        def _build_summary(self, analyzed):
            class Summary:
                def to_dict(_self) -> dict:
                    return {"total_files": len(analyzed), "critical": 0, "high": 0, "medium": 0,
                            "low": len(analyzed), "sensitive_files": 0}
            return Summary()

    config = WinRMEndpointConfig(host="endpoint-01", username="scan", password="secret",
                                 paths=["documents"], read_content=True)
    payload = EndpointScanRequest(host="endpoint-01", username="scan", password="secret",
                                  paths=["documents"], incremental_enabled=False, save_report=False)
    principal = Principal(subject="gate", role="analyst", tenant_id="scale-gate")

    def run(batch_bytes: int, batch_files: int) -> int:
        report = Report()
        # Plain functions, never Mocks: a Mock remembers every call's arguments, and the
        # batches would stay alive in its call list (B4's probe learned this the hard way).
        with mock.patch.dict(os.environ, {"DSPM_ENDPOINT_FETCH_BATCH_BYTES": str(batch_bytes),
                                          "DSPM_ENDPOINT_MAX_FILE_TEXT_BYTES": str(5 * MB)}), \
                mock.patch("backend.app.ENDPOINT_INCREMENTAL_FETCH_BATCH_SIZE", batch_files), \
                mock.patch("backend.app._endpoint_analysis_engine", lambda *a, **k: report), \
                mock.patch("backend.app.WinRMEndpointScanner", Scanner), \
                mock.patch("backend.app._analyze_endpoint_records", analyze), \
                mock.patch("backend.app._apply_compliance", lambda *a, **k: None), \
                mock.patch("backend.app._persist_scan", lambda *a, **k: None):
            tracemalloc.start()
            tracemalloc.reset_peak()
            _run_endpoint_scan_payload(config, payload, principal)
            peak = tracemalloc.get_traced_memory()[1]
            tracemalloc.stop()
        return peak

    scope = files * file_bytes
    one_command = run(512 * MB, files)
    paged = run(32 * MB, 256)
    ratio = round(paged / max(one_command, 1), 3)
    return _check(
        "endpoint memory follows the batch budget",
        "B4 (§7.21)",
        paged <= 2 * 32 * MB and ratio <= 0.5,
        {"paged_mb": round(paged / MB, 1), "one_command_mb": round(one_command / MB, 1), "ratio": ratio},
        "paged peak <= 64 MB and <= half of one delivery",
        f"scope {scope // MB} MB in {files} files",
    )


# --------------------------------------------------------------------------- B7


def finding_model_check(base: Path) -> dict:
    """B7: one value found by three detectors is one finding, and the record is not padded."""
    from discovery.discovery_engine import DSPMDiscoveryEngine

    content = "name: Ana Mammadova\nemail: ana@example.com\ncard number: 4111 1111 1111 1111\n"
    engine = DSPMDiscoveryEngine(_scan_config("scale-gate", base, base / "cache-model", compliance=True))
    analyzed = engine._analyze_record({
        "source": "local", "share": "local", "path": r"C:\Data\customers.csv", "name": "customers.csv",
        "size": len(content), "extension": ".csv", "modified_at": "2026-09-01T00:00:00Z",
        "tenant_id": "scale-gate", "content": content,
    })
    findings = analyzed.get("findings") or []
    pans = [finding for finding in findings if finding.get("canonical_entity_type") == "PAN"]
    emails = [finding for finding in findings if finding.get("canonical_entity_type") == "EMAIL_ADDRESS"]
    frameworks = sorted((pans[0].get("framework_mappings") or []) if pans else [])
    record_bytes = len(json.dumps(analyzed, default=str, ensure_ascii=False))
    ok = len(pans) == 1 and len(emails) == 1 and frameworks == ["GDPR", "PCI DSS"] and record_bytes <= 40_000
    return _check(
        "one card is one finding with both framework tags",
        "B7 (§7.24)",
        ok,
        {"pan_findings": len(pans), "email_findings": len(emails), "frameworks": frameworks,
         "record_bytes": record_bytes},
        "one of each, two framework tags, record <= 40,000 B",
        f"{len(findings)} findings on the fixture",
    )


# ---------------------------------------------------------------------------


def run_gate(*, files: int = 400, quick: bool = False) -> dict:
    """Every envelope, measured. Returns the checks and the ones that failed."""
    if quick:
        files = min(files, 120)
    started = time.perf_counter()
    # Under the repo's gitignored tmp/, because an estate under the session temp
    # directory is skipped by the collector and would scan as nothing (see _corpus).
    (ROOT / "tmp").mkdir(exist_ok=True)
    # ignore_cleanup_errors: Windows will not delete a file whose handle is still open,
    # and a scan leaves the reuse index and the database open until the engine is
    # collected. Without this the gate raises at the end of a passing run, and leaves the
    # directory behind either way - which is how tmp/ fills up with scale-gate-*.
    #
    # The environment is the gate's only for the length of the run. Set and left behind,
    # it pointed every later caller in the same process - every test after
    # test_scale_gate - at a directory this block had already deleted, and they wrote
    # their artifacts into it, re-creating it under tmp/ on every suite run.
    with tempfile.TemporaryDirectory(prefix="scale-gate-", dir=str(ROOT / "tmp"),
                                     ignore_cleanup_errors=True) as temp, \
            mock.patch.dict(os.environ, {
                "DSPM_DB_PATH": str(Path(temp) / "gate.sqlite"),
                "DSPM_ARTIFACT_DIR": str(Path(temp) / "artifacts"),
                "DSPM_SCAN_CACHE_DIR": str(Path(temp) / "scan-cache"),
            }):
        base = Path(temp)
        estate = base / "estate"
        _corpus(estate, files)

        from backend import store

        previous_db_path = store.DB_PATH
        store.DB_PATH = base / "gate.sqlite"
        try:
            store.init_db()
            checks = [write_path_check(store, files)]
            checks.extend(partition_checks(store, estate, base, files))
            checks.append(worker_kill_check(store, estate, base))
            checks.append(endpoint_paging_check(128 if quick else 256))
            checks.append(finding_model_check(base))
        finally:
            store.DB_PATH = previous_db_path

    failures = [f"{check['name']}: {check['measured']} (bound {check['bound']})"
                for check in checks if not check["ok"]]
    return {
        "files": files,
        "quick": quick,
        "elapsed_s": round(time.perf_counter() - started, 1),
        "checks": checks,
        "failures": failures,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--files", type=int, default=400, help="corpus size for the scan checks")
    parser.add_argument("--quick", action="store_true", help="smaller corpus, for a per-PR run")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    metrics = run_gate(files=args.files, quick=args.quick)
    if args.json:
        print(json.dumps({**metrics, "passed": not metrics["failures"]}, indent=2, default=str))
    else:
        print("=== Sentro scale gate (Phase B envelopes) ===")
        print(f"  corpus: {metrics['files']} files, {metrics['elapsed_s']}s")
        for check in metrics["checks"]:
            print(f"  [{'PASS' if check['ok'] else 'FAIL'}] {check['name']}  ({check['gate']})")
            print(f"         measured {check['measured']}   bound {check['bound']}")
            if check["detail"]:
                print(f"         {check['detail']}")
        print("  RESULT:", "PASS" if not metrics["failures"] else "FAIL")
        for failure in metrics["failures"]:
            print(f"    - {failure}")
    return 0 if not metrics["failures"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
