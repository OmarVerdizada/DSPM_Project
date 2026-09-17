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
- **plaintext report files**, only when ``DSPM_RETAIN_REPORT_FILE_DAYS`` is set above zero.
  Phase A stopped writing them by default; the ones already on disk are somebody's data,
  and deleting them is an instruction, not a default.

Scan reports, findings and assets are never touched here.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend import store

logger = logging.getLogger(__name__)


def retention_interval_seconds() -> int:
    """How often housekeeping runs; ``0`` turns it off."""
    try:
        return max(0, min(int(os.getenv("DSPM_RETENTION_INTERVAL_SECONDS", "86400")), 30 * 24 * 3600))
    except ValueError:
        return 86_400


def prune_artifacts_enabled() -> bool:
    """Whether unreferenced artifact objects are collected (``DSPM_RETENTION_PRUNE_ARTIFACTS``). Off by default."""
    return os.getenv("DSPM_RETENTION_PRUNE_ARTIFACTS", "0").strip().lower() in {"1", "true", "yes", "on"}


def report_file_days() -> int:
    """After how many days a plaintext report file is deleted; ``0`` (the default) keeps them all."""
    try:
        return max(0, int(os.getenv("DSPM_RETAIN_REPORT_FILE_DAYS", "0")))
    except ValueError:
        return 0


def plaintext_report_files(report_dir: Path) -> list[Path]:
    """The plaintext scan reports on disk - what Phase A stopped writing by default."""
    try:
        return sorted(path for path in report_dir.glob("*.json") if path.is_file())
    except OSError:
        return []


def _prune_report_files(report_dir: Path, *, days: int, now: datetime, apply: bool) -> dict:
    cutoff = (now - timedelta(days=days)).timestamp()
    stale = []
    for path in plaintext_report_files(report_dir):
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


_stop = threading.Event()
_thread: threading.Thread | None = None
_thread_lock = threading.Lock()


def _loop(report_dir: Path | None, interval: int) -> None:
    while True:
        try:
            run_if_due(report_dir=report_dir)
        except Exception as exc:  # pragma: no cover - housekeeping must never end the thread
            logger.warning("Housekeeping failed: %s", type(exc).__name__)
        # Look often enough that a backend which is only up for part of the day still
        # takes its turn, but let the claim decide whether anything runs.
        if _stop.wait(min(max(60, interval // 24), 3600)):
            return


def start_housekeeping(report_dir: Path | None = None) -> bool:
    """Start the housekeeping sweep; returns whether it runs."""
    global _thread
    interval = retention_interval_seconds()
    if interval <= 0:
        return False
    with _thread_lock:
        if _thread is not None and _thread.is_alive():
            return True
        _stop.clear()
        _thread = threading.Thread(target=_loop, args=(report_dir, interval), name="housekeeping", daemon=True)
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
