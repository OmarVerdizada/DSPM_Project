"""B5: the housekeeping a backend does on its own, so ``data/`` stops growing.

Retention was a tool an operator had to remember to run. This runs it on the same model
as the scan scheduler: once every ``DSPM_RETENTION_INTERVAL_SECONDS`` (a day by default,
``0`` turns it off), claimed through the database so several backends do it once between
them.

What it removes is deliberately narrow:

- **event rows past their window** - alerts and the audit trail, by the same policy the
  retention tool applies (:func:`backend.store.prune_event_tables`), and never for a
  tenant under legal hold;
- **job records** that are finished and old, which the startup sweep already pruned once;
- **unreferenced artifact objects**, only when ``DSPM_RETENTION_PRUNE_ARTIFACTS=1``. It is
  off by default: collecting objects is not retention, and an install should say yes to it
  deliberately;
- **plaintext report files** older than ``DSPM_RETAIN_REPORT_FILE_DAYS`` (90 by default;
  ``0`` keeps them), except a held tenant's. Phase A stopped writing them by default, and
  each is a clear-text copy of a report the encrypted artifact tier still holds, so
  removing it loses no report. Until C0.2 the default was to keep them for ever, which
  made the plaintext copy the longest-lived one; 90 days gives an external reader that
  still collects them (``DSPM_PLAINTEXT_REPORT_EXPORT=1``) a full quarter.

Scan reports, findings and assets are never touched here.

C0.3: the same loop takes the installation's backup set every ``DSPM_BACKUP_SCHEDULE_HOURS``
(``run_backup_if_due``), claimed the same way, so one backend takes it however many run.
And neither job runs against a database a newer release has upgraded (C0.4): a process
at revision N writes nothing to an N+1 database.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend import backup, db, schema_guard, store

logger = logging.getLogger(__name__)

# A failed scheduled backup is tried again after this long, not a whole interval later.
BACKUP_RETRY_SECONDS = 3600


def retention_interval_seconds() -> int:
    """How often housekeeping runs; ``0`` turns it off."""
    try:
        return max(0, min(int(os.getenv("DSPM_RETENTION_INTERVAL_SECONDS", "86400")), 30 * 24 * 3600))
    except ValueError:
        return 86_400


def prune_artifacts_enabled() -> bool:
    """Whether unreferenced artifact objects are collected (``DSPM_RETENTION_PRUNE_ARTIFACTS``). Off by default."""
    return os.getenv("DSPM_RETENTION_PRUNE_ARTIFACTS", "0").strip().lower() in {"1", "true", "yes", "on"}


REPORT_FILE_DAYS_DEFAULT = 90


def report_file_days() -> int:
    """After how many days a plaintext report file is deleted; ``0`` keeps them all.

    An unreadable value keeps the default rather than turning retention off: a typo must
    not quietly bring back keeping plaintext for ever.
    """
    try:
        return max(0, int(os.getenv("DSPM_RETAIN_REPORT_FILE_DAYS", "90")))
    except ValueError:
        return REPORT_FILE_DAYS_DEFAULT


def plaintext_report_files(report_dir: Path) -> list[Path]:
    """The plaintext scan reports on disk - what Phase A stopped writing by default."""
    try:
        return sorted(path for path in report_dir.glob("*.json") if path.is_file())
    except OSError:
        return []


def _prune_report_files(report_dir: Path, *, days: int, now: datetime, apply: bool) -> dict:
    cutoff = (now - timedelta(days=days)).timestamp()
    # A file is named <tenant>_<scan>.json. A held tenant's are kept; matching by prefix
    # can only keep more than that (another tenant whose id begins the same way).
    held = tuple(f"{tenant}_" for tenant in store.tenants_under_legal_hold())
    stale = []
    for path in plaintext_report_files(report_dir):
        if held and path.name.startswith(held):
            continue
        try:
            if path.stat().st_mtime < cutoff:
                stale.append(path)
        except OSError:
            continue
    removed = 0
    if apply:
        for path in stale:
            try:
                path.unlink()
                removed += 1
            except OSError as exc:
                logger.warning("Could not remove the plaintext report %s: %s", path.name, type(exc).__name__)
    return {"data_class": "report_files", "retention_days": days, "eligible_rows": len(stale), "removed_rows": removed}


def run_retention(*, now: datetime | None = None, apply: bool = True, report_dir: Path | None = None) -> dict:
    """Do one housekeeping pass; returns what it removed, data class by data class."""
    moment = now or datetime.now(timezone.utc)
    results = store.prune_event_tables(now=moment, apply=apply)
    jobs_removed = 0
    if apply:
        try:
            jobs_removed = int(store.prune_job_records(30 * 24 * 3600) or 0)
        except Exception as exc:
            logger.warning("Pruning finished job records failed: %s", type(exc).__name__)
    results.append({"data_class": "scan_jobs", "retention_days": 30, "eligible_rows": jobs_removed,
                    "removed_rows": jobs_removed})

    days = report_file_days()
    if days and report_dir is not None:
        results.append(_prune_report_files(report_dir, days=days, now=moment, apply=apply))

    artifacts_result = {"data_class": "artifacts", "eligible_rows": 0, "removed_rows": 0, "skipped": True}
    if prune_artifacts_enabled():
        try:
            from backend import artifacts

            collected = artifacts.prune(store.referenced_artifact_ids()) if apply else 0
            artifacts_result = {"data_class": "artifacts", "eligible_rows": collected,
                                "removed_rows": collected, "skipped": False}
        except Exception as exc:
            logger.warning("Collecting unreferenced artifacts failed: %s", type(exc).__name__)
            artifacts_result = {"data_class": "artifacts", "eligible_rows": 0, "removed_rows": 0,
                                "skipped": True, "error": type(exc).__name__}
    results.append(artifacts_result)
    return {"ran_at": moment.isoformat(), "applied": bool(apply), "data_classes": results}


def run_if_due(*, report_dir: Path | None = None, now: datetime | None = None) -> dict | None:
    """Run housekeeping if nobody has for an interval; returns the pass, or ``None``."""
    interval = retention_interval_seconds()
    if interval <= 0:
        return None
    if not store.claim_housekeeping_run("retention", interval_seconds=interval, now=now):
        return None
    summary = run_retention(now=now, apply=True, report_dir=report_dir)
    removed = sum(int(item.get("removed_rows") or 0) for item in summary["data_classes"])
    logger.info("Housekeeping removed %s rows or objects across %s data classes",
                removed, len(summary["data_classes"]))
    return summary


def backup_check_seconds(interval: int) -> int:
    """How often the loop looks whether a backup is due: a twenty-fourth of the schedule,
    between a minute and a quarter of an hour - so a daily set is taken within 15 minutes
    of falling due, well inside the 26-hour warning."""
    return max(60, min(900, int(interval) // 24))


def backup_schedule_active() -> bool:
    """Whether this backend takes scheduled backups: a schedule is set, and the install names
    its backup key (production always does - it refuses to start without DSPM_BACKUP_KEY)."""
    return backup.schedule_seconds() > 0 and (backup.is_production() or backup.key_configured())


def run_backup_if_due(*, now: datetime | None = None) -> dict | None:
    """Take a backup set if one is due; returns its outcome, or ``None`` when not due.

    Due when the newest VERIFIED set is about to be older than the schedule, or the last
    attempt failed. A set the upgrade or an operator took (``backup create --verify``)
    therefore counts, instead of being followed by a second one. The claim through the
    database decides which backend takes it; a failure makes the next claim possible after
    BACKUP_RETRY_SECONDS rather than a whole interval.
    """
    if not backup_schedule_active():
        return None
    interval = backup.schedule_seconds()
    check = backup_check_seconds(interval)
    moment = now or datetime.now(timezone.utc)
    verified = next((item for item in backup.backup_sets() if item["verified"]), None)
    attempt = backup.last_attempt()
    failed = bool(attempt) and not attempt.get("ok")
    if not failed and verified is not None and (moment - verified["created_at"]).total_seconds() + check < interval:
        return None
    if not store.claim_housekeeping_run("backup", interval_seconds=interval - check, now=moment):
        return None
    # C10: the backup's own work across every tenant is named as the backup purpose (pg_dump
    # and the row counts name it in their sessions); its audit row is the installation's.
    with db.platform_scope(backup.BACKUP_PURPOSE):
        outcome = backup.run_backup_set(trigger="schedule")
    if not outcome["ok"]:
        store.retry_housekeeping_run("backup", interval_seconds=interval - check,
                                     retry_seconds=BACKUP_RETRY_SECONDS, now=moment)
    return outcome


def run_due_jobs(report_dir: Path | None = None) -> dict:
    """One pass of the loop: retention, then the backup, each only when due. Nothing runs on
    a database a newer release has upgraded (C0.4, backend.schema_guard) - not even a
    backup, whose audit row would be a write in a shape this build may not know."""
    if schema_guard.stand_down("housekeeping"):
        return {"skipped": "the database schema is newer than this build"}
    ran: dict = {}
    for name, job in (("retention", lambda: run_if_due(report_dir=report_dir)), ("backup", run_backup_if_due)):
        try:
            ran[name] = job()
        except Exception as exc:  # one job failing must not keep the other from running
            logger.warning("Housekeeping (%s) failed: %s", name, type(exc).__name__)
            ran[name] = {"error": type(exc).__name__}
    return ran


_stop = threading.Event()
_thread: threading.Thread | None = None
_thread_lock = threading.Lock()


def _wait_seconds() -> int:
    """How long the loop sleeps between passes (0: nothing to do, no loop)."""
    waits = []
    interval = retention_interval_seconds()
    if interval > 0:
        # Look often enough that a backend which is only up for part of the day still
        # takes its turn, but let the claim decide whether anything runs.
        waits.append(min(max(60, interval // 24), 3600))
    if backup_schedule_active():
        waits.append(backup_check_seconds(backup.schedule_seconds()))
    return min(waits) if waits else 0


def _loop(report_dir: Path | None, wait: int) -> None:
    while True:
        try:
            run_due_jobs(report_dir)
        except Exception as exc:  # pragma: no cover - housekeeping must never end the thread
            logger.warning("Housekeeping failed: %s", type(exc).__name__)
        if _stop.wait(wait):
            return


def start_housekeeping(report_dir: Path | None = None) -> bool:
    """Start the housekeeping sweep (retention and the backup schedule); returns whether it runs."""
    global _thread
    wait = _wait_seconds()
    if wait <= 0:
        return False
    with _thread_lock:
        if _thread is not None and _thread.is_alive():
            return True
        _stop.clear()
        _thread = threading.Thread(target=_loop, args=(report_dir, wait), name="housekeeping", daemon=True)
        _thread.start()
    return True


def stop_housekeeping() -> None:
    global _thread
    _stop.set()
    with _thread_lock:
        thread = _thread
        _thread = None
    if thread is not None and thread.is_alive():
        thread.join(timeout=5.0)
