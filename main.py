from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# C11: the one configuration source (DSPM_CONFIG_FILE, or --config) is applied before any
# product module is imported - several read their settings when they load. A refused
# configuration stops every command here, except `config check`, which exists to show it.
if __name__ == "__main__":
    from backend import config as _config

    if _config.command_from_argv(sys.argv[1:]) != "config":
        try:
            _config.bootstrap(_config.config_path_from_argv(sys.argv[1:]))
        except _config.ConfigError as _refused:
            print(_refused, file=sys.stderr)
            raise SystemExit(2)

import uvicorn  # noqa: E402

from backend.compliance_service import enrich_report_with_compliance, normalize_framework_ids  # noqa: E402
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig  # noqa: E402
from scripts.logger import get_logger  # noqa: E402
from scripts.report import generate_report  # noqa: E402

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
# to the others until the entry expires - a staleness question, which asking for
# workers answers by turning them off rather than leaving the operator to read a
# warning. Token revocation is no longer among them: since C1 only a "revoked"
# answer is cached, so no worker - and no separately started server, which this
# switch never reached - can go on accepting a token another one revoked.
_PER_PROCESS_CACHE_SETTINGS = (
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
    from backend import logging_setup

    # C11: one set of handlers - rotating file when DSPM_LOG_DIR is set, standard error
    # always - and every line through the redacting filter, uvicorn's included.
    logging_setup.configure("backend")
    is_production = os.getenv("DSPM_ENV", "local").lower() in {"prod", "production"}
    if args.reload and is_production:
        raise SystemExit("--reload is disabled when DSPM_ENV=production")
    if is_production:
        # C5: where the backend listens is decided here; the rest of the boundary is
        # checked again when the app is imported.
        from backend import deployment_boundary

        problems = deployment_boundary.bind_problems(args.host)
        if problems:
            raise SystemExit(deployment_boundary.refusal(problems))
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
        # C5: uvicorn believes X-Forwarded-For and -Proto from 127.0.0.1 by default,
        # whatever DSPM_TRUSTED_PROXIES says - so behind a proxy on this host any local
        # program could name its own address. The app decides (backend/client_address).
        proxy_headers=False,
        # C11: uvicorn keeps the handlers configured above (with --reload its server runs
        # in a child process that has none, so there it keeps its own).
        **({} if args.reload else {"log_config": None}),
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

    from backend import db, logging_setup, store

    logging_setup.configure("worker")
    queue = work_queue_from_env()
    worker_id = args.worker_id or default_worker_id()
    logger.info("Partition worker %s is taking work from the %s", worker_id, type(queue).__name__)
    # P4: a worker polls the ledger all day; see db.hold_sqlite_open.
    db.hold_sqlite_open(store.DB_PATH)
    try:
        run_worker(queue, rebuild_scan_config, worker_id=worker_id)
    except KeyboardInterrupt:
        logger.info("Partition worker %s stopped", worker_id)
    finally:
        db.release_sqlite_anchor()


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
            if result["problem_count"] > 25:
                print(f"         ... and {result['problem_count'] - 25} more")
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


def mfa_reset(args: argparse.Namespace) -> int:
    """Remove an account's second factor from the host (C2 break-glass).

    For the built-in administrator, whose factor the console will not reset, and for any
    account whose administrators are locked out themselves. Whoever can run this already
    holds the host, the database and the vault key. The account's sessions end, it sets up
    a new factor at its next sign-in, and the reset is in the audit trail as done "by host".
    """
    from backend.store import audit, delete_user_mfa, get_user, revoke_sessions_for_user

    user = get_user(args.username.strip().lower())
    if user is None:
        print(f"No account {args.username!r}.")
        return 1
    removed = delete_user_mfa(user["tenant_id"], user["username"])
    ended = revoke_sessions_for_user(user["username"])
    audit(user["tenant_id"], "host", "auth.mfa_reset",
          {"username": user["username"], "by": "host", "had_factor": removed, "sessions_ended": ended})
    print(f"{user['username']}: second factor {'removed' if removed else 'was not set up'}; "
          f"{ended} session(s) ended. It is set up again at the next sign-in.")
    return 0


def config_check(args: argparse.Namespace) -> int:
    """Validate the configuration and show the effective settings - each with where it came
    from, a secret only as "(set)" - and every warning and refusal. Exit 1 when refused."""
    from backend import config

    raw = args.config or os.environ.get(config.CONFIG_ENV) or ""
    effective = config.resolve(os.environ, Path(raw) if raw else None)
    print(f"configuration: {raw or '(environment only)'}")
    print(f"mode:          {'production' if effective.production else 'local / evaluation'}")
    rows = effective.describe(show_defaults=args.all)
    width = max((len(row[0]) for row in rows), default=12)
    for name, shown, source in rows:
        print(f"  {name:<{width}}  {shown:<24}  {source}")
    for warning in effective.warnings:
        print(f"warning: {warning}")
    for error in effective.errors:
        print(f"REFUSED: {error}")
    if effective.errors:
        print("configuration is NOT valid")
        return 1
    print("configuration is valid")
    return 0


def migrate_command(args: argparse.Namespace) -> int:
    """Schema revisions. The database is opened without converging it (what `migrations`
    does on its own), so `status` reads what is there and `upgrade` is the only writer."""
    os.environ["DSPM_MIGRATIONS_CLI"] = "1"
    from backend import migrations

    if args.migrate_command == "upgrade":
        migrations.upgrade()
    info = migrations.status()
    summary = {"backend": info["backend"], "applied_revision": info["applied_revision"],
               "expected_revision": info["expected_revision"],
               "pending": [item["revision"] for item in info["pending"]]}
    if args.json:
        print(json.dumps(summary))
    else:
        print(f"{info['backend']}: schema at revision {info['applied_revision']}, "
              f"this build expects {info['expected_revision']}"
              + (f"; pending {summary['pending']}" if summary["pending"] else ""))
    return 0


def _record_backup_attempt(ok: bool, error: str, stage: str = "create") -> None:
    """D11: what the last backup attempt did, for /metrics, readiness and the installation's
    alerts - the time and the error's type, never its text (a failing pg_dump can echo a URL)."""
    try:
        from backend import backup

        backup.record_attempt(ok, error, stage=stage, trigger="command line")
    except Exception:  # recording must never change what the backup itself did
        pass


def backup_command(args: argparse.Namespace) -> int:
    """Encrypted backups of the database and the artifact store (C11; C0.3's first half)."""
    os.environ["DSPM_MIGRATIONS_CLI"] = "1"
    from backend import backup

    def emit(document: dict, text: str) -> None:
        print(json.dumps(document) if args.json else text)

    if args.backup_command == "create":
        try:
            manifest = backup.create_backup()
        except Exception as exc:
            _record_backup_attempt(False, type(exc).__name__)
            raise
        document = {"manifest": str(manifest),
                    "schema_revision": json.loads(manifest.read_text(encoding="utf-8")).get("schema_revision")}
        if args.verify:
            try:
                report = backup.verify_backup(manifest)
                if report["ok"]:
                    # C0.3: a verified set is what retention keeps and readiness measures.
                    backup.mark_verified(manifest)
            except Exception as exc:
                _record_backup_attempt(False, type(exc).__name__, "verify")
                raise
            document.update({"verified": report["ok"], "problems": report["problems"]})
            _record_backup_attempt(report["ok"], "" if report["ok"] else backup.BackupVerifyError.__name__,
                                   "done" if report["ok"] else "verify")
        else:
            _record_backup_attempt(True, "")
        if args.keep:
            document["pruned"] = backup.prune_backups(keep=args.keep)
        emit(document, f"backup {manifest}" + ("" if not args.verify else
                                                (" - verified" if document["verified"] else
                                                 " - VERIFY FAILED: " + "; ".join(document["problems"]))))
        return 0 if document.get("verified", True) else 1
    if args.backup_command == "verify":
        report = backup.verify_backup(Path(args.manifest))
        emit(report, ("verified: " if report["ok"] else "FAILED: ") + (", ".join(report["problems"]) or args.manifest))
        return 0 if report["ok"] else 1
    if args.backup_command == "restore":
        if not args.yes:
            print("Restoring replaces the database (the current one is kept beside it). Add --yes to do it.")
            return 2
        result = backup.restore_backup(Path(args.manifest))
        emit(result, f"restored {result['restored']} at schema revision {result['schema_revision']}; "
                     f"the previous database is {result['previous_database']}")
        return 0
    rows = []
    for path in backup.list_manifests():
        manifest = json.loads(path.read_text(encoding="utf-8"))
        rows.append({"manifest": str(path), "created_at": manifest.get("created_at"), "kind": manifest.get("kind"),
                     "schema_revision": manifest.get("schema_revision"), "verified": bool(manifest.get("verified_at"))})
    emit({"backups": rows}, "\n".join(f"{row['created_at']}  {row['kind']:<8} rev {row['schema_revision']}  "
                                      f"{'verified  ' if row['verified'] else 'unverified'}  {row['manifest']}"
                                      for row in rows) or "no backups")
    return 0


def licence_command(args: argparse.Namespace) -> int:
    """The offline licence (D10): install a licence file, or show the one installed. The
    recovery path when the console cannot be reached, or the licence ran out: copy the
    renewal to the host and run `python main.py licence install <file>`."""
    from backend import licensing

    if args.licence_command == "install":
        try:
            licence = licensing.install(Path(args.file).read_bytes())
        except (OSError, licensing.LicenceError) as exc:
            print(f"REFUSED: {exc}")
            return 1
        from backend import store

        store.audit("default", "host", "licence.installed", {
            "licence_id": licence["licence_id"], "customer": licence["customer"], "expires_at": licence["expires_at"],
            "key_id": licence["key_id"], "source": "command line"})
        print(f"Installed licence {licence['licence_id']} for {licence['customer']}, valid until {licence['expires_at']}.")
        return 0
    status = licensing.status(licensing.installed())
    print(json.dumps(status, indent=2) if args.json else status["message"])
    return 0 if status["state"] in {"valid", "grace"} else 1


def package_command(args: argparse.Namespace) -> int:
    """Check an update package with THIS install's verifier and trust file before running
    anything from it (D10)."""
    from backend import signing

    trust_path = Path(args.trust) if args.trust else None
    if trust_path is None:
        from backend import licensing

        trust_path = licensing.trust_file()
    installed = {"commit_time": args.installed_commit_time} if args.installed_commit_time else None
    try:
        result = signing.verify_package(Path(args.package), signing.load_trust(trust_path), installed=installed,
                                        allow_unsigned=args.allow_unsigned, allow_downgrade=args.allow_downgrade)
    except signing.TrustError as exc:
        print(f"REFUSED: {exc}")
        return 1
    print(json.dumps(result) if args.json else
          f"verified {result['label']}: {result['files']} files, signed by {result['signed_by'] or 'nobody (accepted unsigned)'}")
    return 0


def vault_command(args: argparse.Namespace) -> int:
    """The vault's keys (C12): status, rotation, rollback and escrow. Run as an
    administrator, with the services running or not - a rotation never leaves a sealed
    value its key ring cannot open. No key or passphrase is ever printed or taken from
    the command line."""
    from backend import vault, vault_keys

    try:
        if args.vault_command == "status":
            result = vault.status()
        elif args.vault_command == "rotate":
            result = vault.rotate(resume=args.resume, skip_unreadable=args.skip_unreadable)
        elif args.vault_command == "rollback":
            result = vault.rollback(skip_unreadable=args.skip_unreadable)
        elif getattr(args, "escrow_command", "") == "export":
            result = vault.export_escrow(Path(args.out), vault_keys.read_passphrase(args.passphrase_file, confirm=True))
        elif getattr(args, "escrow_command", "") == "verify":
            result = vault.verify_escrow(Path(args.file), vault_keys.read_passphrase(args.passphrase_file))
        else:
            result = vault.recover_escrow(Path(args.file), vault_keys.read_passphrase(args.passphrase_file),
                                          Path(args.out), force=args.force, accept_missing=args.accept_missing)
    except (vault_keys.VaultKeyError, OSError) as refused:
        # OSError: an unreadable escrow or passphrase file. The message names the file,
        # never its content.
        print(f"REFUSED: {refused}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=None if args.json else 2))
    return 0 if result.get("ok", True) else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DSPM scanner for AD file-server data discovery.")
    parser.add_argument("--config", default=None,
                        help="The configuration file (TOML, [settings]); default: DSPM_CONFIG_FILE.")
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

    mfa_parser = subparsers.add_parser("mfa", help="Second-factor tools for the host operator.")
    mfa_commands = mfa_parser.add_subparsers(dest="mfa_command", required=True)
    reset_parser = mfa_commands.add_parser("reset", help="Remove an account's second factor and end its sessions.")
    reset_parser.add_argument("username", help="The account key (the built-in administrator is 'admin').")
    reset_parser.set_defaults(func=mfa_reset)

    config_parser = subparsers.add_parser("config", help="The configuration file and settings (C11).")
    config_commands = config_parser.add_subparsers(dest="config_command", required=True)
    check_parser = config_commands.add_parser("check", help="Validate it and show the effective settings.")
    check_parser.add_argument("--all", action="store_true", help="Show the defaults too.")
    check_parser.set_defaults(func=config_check)

    migrate_parser = subparsers.add_parser("migrate", help="Database schema revisions.")
    migrate_commands = migrate_parser.add_subparsers(dest="migrate_command", required=True)
    for name, text in (("status", "Show the applied and expected revision."),
                       ("upgrade", "Apply the pending revisions (the services should be stopped).")):
        command = migrate_commands.add_parser(name, help=text)
        command.add_argument("--json", action="store_true")
        command.set_defaults(func=migrate_command)

    vault_parser = subparsers.add_parser("vault", help="The credential vault's keys (C12).")
    vault_commands = vault_parser.add_subparsers(dest="vault_command", required=True)
    vault_commands.add_parser("status", help="The active key, the keys held, and what each seals.")
    rotate_parser = vault_commands.add_parser("rotate", help="Make a new key active and re-seal everything with it.")
    rotate_parser.add_argument("--resume", action="store_true", help="Finish a rotation that stopped part-way.")
    rollback_parser = vault_commands.add_parser("rollback", help="Make the previous key active again and re-seal with it.")
    for command in (rotate_parser, rollback_parser):
        command.add_argument("--skip-unreadable", action="store_true",
                             help="Leave values no key in the ring opens as they are (they stay unreadable).")
    escrow_parser = vault_commands.add_parser("escrow", help="The key ring, encrypted with a passphrase.")
    escrow_commands = escrow_parser.add_subparsers(dest="escrow_command", required=True)
    escrow_export = escrow_commands.add_parser("export", help="Write an escrow of the key ring.")
    escrow_export.add_argument("--out", required=True)
    escrow_verify = escrow_commands.add_parser("verify", help="Check an escrow opens and holds every key in use.")
    escrow_verify.add_argument("file")
    escrow_recover = escrow_commands.add_parser("recover", help="Write the key ring back from an escrow.")
    escrow_recover.add_argument("file")
    escrow_recover.add_argument("--out", required=True, help="The key ring file to write (DSPM_VAULT_KEYRING).")
    escrow_recover.add_argument("--force", action="store_true", help="Replace an existing key ring (it is kept beside).")
    escrow_recover.add_argument("--accept-missing", action="store_true",
                                help="Recover an escrow that cannot open everything sealed now.")
    for command in (escrow_export, escrow_verify, escrow_recover):
        command.add_argument("--passphrase-file", default=None,
                             help="A file whose first line is the passphrase (else it is asked for).")
    for command in (vault_commands.choices["status"], rotate_parser, rollback_parser,
                    escrow_export, escrow_verify, escrow_recover):
        command.add_argument("--json", action="store_true")
        command.set_defaults(func=vault_command)

    licence_parser = subparsers.add_parser("licence", help="The offline licence (D10).")
    licence_commands = licence_parser.add_subparsers(dest="licence_command", required=True)
    licence_install = licence_commands.add_parser("install", help="Verify and install a licence file.")
    licence_install.add_argument("file")
    licence_status = licence_commands.add_parser("status", help="The installed licence and what it allows.")
    licence_status.add_argument("--json", action="store_true")
    for command in (licence_install, licence_status):
        command.set_defaults(func=licence_command)

    package_parser = subparsers.add_parser("package", help="Update packages (D10).")
    package_commands = package_parser.add_subparsers(dest="package_command", required=True)
    package_verify = package_commands.add_parser(
        "verify", help="Check a package's files and its publisher's signature against this install's trust file.")
    package_verify.add_argument("--package", required=True)
    package_verify.add_argument("--trust", help="The trust file (default: DSPM_TRUST_FILE).")
    package_verify.add_argument("--installed-commit-time", type=int, default=0)
    package_verify.add_argument("--allow-unsigned", action="store_true")
    package_verify.add_argument("--allow-downgrade", action="store_true")
    package_verify.add_argument("--json", action="store_true")
    package_verify.set_defaults(func=package_command)

    backup_parser = subparsers.add_parser("backup", help="Encrypted backups of the database and artifacts.")
    backup_commands = backup_parser.add_subparsers(dest="backup_command", required=True)
    create_parser = backup_commands.add_parser("create", help="Take a backup (SQLite or PostgreSQL).")
    create_parser.add_argument("--verify", action="store_true", help="Decrypt it and check it before reporting.")
    create_parser.add_argument("--keep", type=int, default=0, help="Then keep only the newest N backup sets.")
    verify_backup_parser = backup_commands.add_parser("verify", help="Check a backup set against its manifest.")
    verify_backup_parser.add_argument("manifest")
    restore_parser = backup_commands.add_parser(
        "restore", help="Put a backup in place of the database (SQLite, or PostgreSQL in one transaction).")
    restore_parser.add_argument("manifest")
    restore_parser.add_argument("--yes", action="store_true", help="Confirm replacing the database.")
    list_parser = backup_commands.add_parser("list", help="The backup sets in DSPM_BACKUP_DIR.")
    for command in (create_parser, verify_backup_parser, restore_parser, list_parser):
        command.add_argument("--json", action="store_true")
        command.set_defaults(func=backup_command)

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


def main(argv: list[str] | None = None) -> int:
    require_supported_python()
    parser = build_parser()
    args = parser.parse_args(argv)
    result = args.func(args)
    return int(result or 0)


if __name__ == "__main__":
    raise SystemExit(main())
