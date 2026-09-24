from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import uvicorn

from backend.compliance_service import enrich_report_with_compliance, normalize_framework_ids
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from scripts.logger import get_logger
from scripts.report import generate_report

logger = get_logger(__name__)

# The supported floor, kept in step with requirements.txt's header and CI's lowest
# matrix leg by tests/test_supported_python_floor.py.
MINIMUM_PYTHON = (3, 12)


def run_scan(args: argparse.Namespace) -> None:
    allowed_extensions = [
        item.strip()
        for item in (args.extensions or "").split(",")
        if item.strip()
    ]
    config = ScanConfig(
        server=args.server,
        username=args.username,
        password=args.password,
        domain=args.domain,
        local_path=args.local_path,
        max_depth=args.max_depth,
        allowed_extensions=allowed_extensions,
        extension_filter_enabled=bool(allowed_extensions),
        include_hidden=args.include_hidden,
        include_system=args.include_system,
        hidden_filter_enabled=args.only_hidden,
        system_filter_enabled=args.only_system,
        compliance_enabled=args.compliance,
        compliance_frameworks=normalize_framework_ids(args.frameworks.split(",")) if args.frameworks else [],
    )
    engine = DSPMDiscoveryEngine(config)
    report = engine.run()
    data = enrich_report_with_compliance(report.to_dict(), args.compliance, config.compliance_frameworks)

    output_path = Path(args.output)
    generate_report(data, output_path)

    logger.info("Scan completed: %s files analyzed", report.summary.total_files)
    logger.info("Report saved to %s", output_path)


# Caches that live in one process and are invalidated by that same process.
# With several workers each keeps its own copy, so a write in one is invisible
# to the others until the entry expires. Two of these are only a staleness
# question; the revocation one is a security question, because a token revoked
# in worker A would still be accepted by worker B for the length of its TTL.
# Asking for workers therefore turns them off rather than leaving the operator
# to read a warning.
_PER_PROCESS_CACHE_SETTINGS = (
    ("DSPM_TOKEN_REVOCATION_CACHE_SECONDS", "a revoked token would outlive its revocation in the other workers"),
    ("DSPM_TENANT_EXISTS_CACHE_SECONDS", "a deleted tenant would keep resolving in the other workers"),
    ("DSPM_READINESS_CACHE_SECONDS", "a completed backfill would not be seen by the other workers"),
    ("DSPM_INVENTORY_COUNT_CACHE_SECONDS", "a saved scan would not clear the other workers' counts"),
    ("DSPM_INVENTORY_FACETS_CACHE_SECONDS", "a saved scan would not clear the other workers' facets"),
)


def _disable_per_process_caches(logger) -> None:
    for name, why in _PER_PROCESS_CACHE_SETTINGS:
        if os.environ.get(name) == "0":
            continue
        os.environ[name] = "0"
        logger.warning("Multiple workers: %s=0 - %s.", name, why)


def serve(args: argparse.Namespace) -> None:
    is_production = os.getenv("DSPM_ENV", "local").lower() in {"prod", "production"}
    if args.reload and is_production:
        raise SystemExit("--reload is disabled when DSPM_ENV=production")
    workers = max(1, int(getattr(args, "workers", 1) or 1))
    if workers > 1:
        if args.reload:
            raise SystemExit("--reload runs a single process; drop it to use --workers")
        # SQLite serialises writers across processes even in WAL, so several
        # workers help a read-heavy console and hurt during a scan. PostgreSQL
        # is the backend this flag exists for.
        if not os.getenv("DSPM_DB_URL", "").strip():
            logger.warning(
                "Multiple workers on SQLite: reads scale, but writers still serialise "
                "across processes. PostgreSQL (DSPM_DB_URL) is the backend for this."
            )
        _disable_per_process_caches(logger)
    uvicorn.run(
        "backend.app:app", host=args.host, port=args.port,
        reload=args.reload, workers=workers if workers > 1 else None,
    )


def work(args: argparse.Namespace) -> None:
    """Run scan partitions from the work queue until interrupted (B3).

    Workers take partitions straight from the ledger, so they need nothing but the
    database. Any number of them can share the scans the console starts; the ledger's
    leases decide who runs what.
    """
    from backend.app import rebuild_scan_config
    from backend.partition_worker import default_worker_id, run_worker
    from backend.work_queue import work_queue_from_env

    queue = work_queue_from_env()
    worker_id = args.worker_id or default_worker_id()
    logger.info("Partition worker %s is taking work from the %s", worker_id, type(queue).__name__)
    try:
        run_worker(queue, rebuild_scan_config, worker_id=worker_id)
    except KeyboardInterrupt:
        logger.info("Partition worker %s stopped", worker_id)


def audit_verify(args: argparse.Namespace) -> None:
    """Check the audit trail's hash chains (C4); exit 1 if any tenant's chain is broken.

    Reads the database this install is configured for (DSPM_DB_URL / DSPM_DB_PATH), and
    changes nothing in it. A broken chain names the rows: a changed row no longer matches
    its hash, a deleted one leaves a gap, and cut-off newest rows leave the chain shorter
    than its head. Rows written before revision 0022 are sealed as of the upgrade, and the
    report says so - nothing proves they were untouched before it.
    """
    import json

    from backend.store import verify_audit_chain

    results = verify_audit_chain(args.tenant or None)
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for result in results:
            notes = []
            if result["sealed_through_seq"]:
                notes.append(f"rows 1-{result['sealed_through_seq']} sealed at upgrade {result['sealed_at'][:19]}")
            if result["pruned_through_seq"]:
                notes.append(f"rows up to {result['pruned_through_seq']} removed by retention")
            suffix = f" ({'; '.join(notes)})" if notes else ""
            print(f"{'OK    ' if result['ok'] else 'BROKEN'} {result['tenant_id']}: {result['rows']} rows{suffix}")
            for problem in result["problems"][:25]:
                print(f"         seq {problem['seq']}: {problem['problem']}")
            if len(result["problems"]) > 25:
                print(f"         ... and {len(result['problems']) - 25} more")
    raise SystemExit(0 if all(result["ok"] for result in results) else 1)


def audit_forward(args: argparse.Namespace) -> None:
    """Drain the SIEM outbox once and say what happened (C4); exit 1 if anything failed."""
    from backend.siem import drain, siem_target

    if siem_target() is None:
        raise SystemExit("DSPM_SIEM_URL is not set: there is no SIEM to forward to.")
    total = {"sent": 0, "failed": 0, "pending": 0}
    while True:
        result = drain()
        total["sent"] += result["sent"]
        total["failed"] += result["failed"]
        total["pending"] = result["pending"]
        if result["failed"] or not result["sent"]:
            break
    print(f"sent {total['sent']}, failed {total['failed']}, still waiting {total['pending']}")
    raise SystemExit(1 if total["failed"] else 0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DSPM scanner for AD file-server data discovery.")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Run a one-time discovery scan.")
    scan_parser.add_argument("--server", default="", help="SMB/AD file server hostname or IP.")
    scan_parser.add_argument("--username", default="", help="Domain username.")
    scan_parser.add_argument("--password", default="", help="Domain password.")
    scan_parser.add_argument("--domain", default="WORKGROUP", help="AD domain or workgroup.")
    scan_parser.add_argument("--local-path", default="enterprise_test_data", help="Local folder fallback/sample data path.")
    scan_parser.add_argument("--max-depth", type=int, default=4, help="Maximum recursive SMB folder depth.")
    scan_parser.add_argument("--extensions", default="", help="Comma-separated extensions to scan, e.g. .py,.docx,.pdf.")
    scan_parser.add_argument("--include-hidden", action="store_true", help="Include hidden files in an unrestricted scan.")
    scan_parser.add_argument("--include-system", action="store_true", help="Include system files in an unrestricted scan.")
    scan_parser.add_argument("--only-hidden", action="store_true", help="Scan only hidden files, optionally combined with --extensions.")
    scan_parser.add_argument("--only-system", action="store_true", help="Scan only system files, optionally combined with --extensions.")
    scan_parser.add_argument("--compliance", action="store_true", help="Enable compliance classifiers and mapping.")
    scan_parser.add_argument("--frameworks", default="", help="Comma-separated compliance frameworks, e.g. gdpr,pci_dss.")
    scan_parser.add_argument("--output", default="report.json", help="Output report JSON path.")
    scan_parser.set_defaults(func=run_scan)

    serve_parser = subparsers.add_parser("serve", help="Start the backend API and dashboard.")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8000)
    serve_parser.add_argument("--reload", action="store_true")
    serve_parser.add_argument(
        "--workers", type=int, default=1,
        help="Worker processes. More than one disables the per-process caches "
             "(see DSPM_* cache settings); PostgreSQL is the backend it is for.",
    )
    serve_parser.set_defaults(func=serve)

    worker_parser = subparsers.add_parser(
        "worker", help="Run scan partitions queued in the database ledger.",
    )
    worker_parser.add_argument(
        "--worker-id", default="", help="The name leases and the queue know this worker by; defaults to host:pid.",
    )
    worker_parser.set_defaults(func=work)

    audit_parser = subparsers.add_parser("audit", help="Audit trail tools.")
    audit_commands = audit_parser.add_subparsers(dest="audit_command", required=True)
    verify_parser = audit_commands.add_parser("verify", help="Check every tenant's audit hash chain.")
    verify_parser.add_argument("--tenant", default="", help="Check one tenant only.")
    verify_parser.add_argument("--json", action="store_true", help="Print the full result as JSON.")
    verify_parser.set_defaults(func=audit_verify)
    forward_parser = audit_commands.add_parser(
        "forward", help="Send the audit events waiting for the SIEM (DSPM_SIEM_URL) now, once.")
    forward_parser.set_defaults(func=audit_forward)

    parser.set_defaults(func=serve)
    return parser


def require_supported_python(version: tuple[int, int] | None = None) -> None:
    """Refuse an interpreter below the supported floor, with the reason.

    The floor is where the dependency lock is generated and the suite runs (roadmap
    M0/Q3). Older interpreters resolve a different tree, so an install that "worked"
    on one would not be the tree anything was tested against. Said here, once, rather
    than as an import error three frames deep in a dependency.
    """
    running = version or sys.version_info[:2]
    if running < MINIMUM_PYTHON:
        floor = ".".join(str(part) for part in MINIMUM_PYTHON)
        raise SystemExit(
            f"Sentro needs Python {floor} or newer; this interpreter is "
            f"{'.'.join(str(part) for part in running)}. Install {floor}+ and reinstall the "
            f"dependencies with: pip install --require-hashes -r requirements.lock"
        )


def main() -> None:
    require_supported_python()
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
