from __future__ import annotations

import argparse
import os
from pathlib import Path

import uvicorn

from backend.compliance_service import enrich_report_with_compliance, normalize_framework_ids
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from scripts.logger import get_logger
from scripts.report import generate_report

logger = get_logger(__name__)


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

    parser.set_defaults(func=serve)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
