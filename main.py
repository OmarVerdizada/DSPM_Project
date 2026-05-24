from __future__ import annotations

import argparse
from pathlib import Path

import uvicorn

from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from scripts.logger import get_logger
from scripts.report import generate_report

logger = get_logger(__name__)


def run_scan(args: argparse.Namespace) -> None:
    config = ScanConfig(
        server=args.server,
        username=args.username,
        password=args.password,
        domain=args.domain,
        local_path=args.local_path,
        max_depth=args.max_depth,
    )
    engine = DSPMDiscoveryEngine(config)
    report = engine.run()

    output_path = Path(args.output)
    generate_report(report, output_path)

    logger.info("Scan completed: %s files analyzed", report.summary.total_files)
    logger.info("Report saved to %s", output_path)


def serve(args: argparse.Namespace) -> None:
    uvicorn.run("backend.app:app", host=args.host, port=args.port, reload=args.reload)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DSPM scanner for AD file-server data discovery.")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Run a one-time discovery scan.")
    scan_parser.add_argument("--server", default="", help="SMB/AD file server hostname or IP.")
    scan_parser.add_argument("--username", default="", help="Domain username.")
    scan_parser.add_argument("--password", default="", help="Domain password.")
    scan_parser.add_argument("--domain", default="WORKGROUP", help="AD domain or workgroup.")
    scan_parser.add_argument("--local-path", default="test_data", help="Local folder fallback/sample data path.")
    scan_parser.add_argument("--max-depth", type=int, default=4, help="Maximum recursive SMB folder depth.")
    scan_parser.add_argument("--output", default="report.json", help="Output report JSON path.")
    scan_parser.set_defaults(func=run_scan)

    serve_parser = subparsers.add_parser("serve", help="Start the backend API and dashboard.")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8000)
    serve_parser.add_argument("--reload", action="store_true")
    serve_parser.set_defaults(func=serve)

    parser.set_defaults(func=serve)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
