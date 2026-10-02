"""C0.4: one answer to "has a newer release upgraded the database under this process?"

A process started at revision N must stop writing to a database that is at N+1: the
newer release may have changed the shape of what it would write. Everything that writes
asks here - the HTTP guard in front of the data routes (backend.app.schema_guard), the
scan worker (backend.partition_worker), and every background writer at the top of each
pass: the scan scheduler, the scan resumer, the SIEM forwarder, the alert deliverer, the
installation's own alerts, the search reconciler and housekeeping (retention and the
backup schedule). A pass already under way finishes its current item; the next one does
nothing until the matching release runs.

The database is asked at most once every DSPM_SCHEMA_CHECK_SECONDS (30), so a database
moved ahead is noticed within one interval, and asking costs nothing in between. Each
writer logs once when it pauses and once when it resumes - not once per pass.
"""

from __future__ import annotations

import logging
import os
import threading
import time

logger = logging.getLogger(__name__)

# One state for the whole process. backend.app keeps its old name for it (_SCHEMA_GUARD),
# and so does backend.partition_worker (_SCHEMA_STATE): setting "checked" to -inf makes the
# next question go to the database.
STATE: dict = {"checked": float("-inf"), "problem": "", "revision": None}
_lock = threading.Lock()
_paused: set[str] = set()


def check_seconds() -> float:
    try:
        return max(1.0, float(os.getenv("DSPM_SCHEMA_CHECK_SECONDS", "30")))
    except ValueError:
        return 30.0


def _revision() -> dict | None:
    try:
        from backend import migrations, store

        with store._connect() as conn:
            return {"applied": migrations.current_revision(conn), "expected": migrations.expected_revision()}
    except Exception:  # an unreachable database is readiness's to report, not a schema mismatch
        return None


def problem() -> str:
    """Why this build must not write now ("" when it may). Asks the database at most once
    per check interval; in between, the last answer."""
    now = time.monotonic()
    with _lock:
        if now - STATE["checked"] < check_seconds():
            return STATE["problem"]
        STATE["checked"] = now
    revision = _revision()
    found = ""
    if revision is not None and revision["applied"] > revision["expected"]:
        found = (f"The database schema is at revision {revision['applied']}, newer than this build's "
                 f"{revision['expected']}: another Sentro release has upgraded it. This server stops "
                 f"serving data until the matching release is running.")
    with _lock:
        if found and not STATE["problem"]:
            logger.error(found)
        STATE["problem"] = found
        STATE["revision"] = revision if found else None
    return found


def revision() -> dict:
    """The applied and expected revisions behind the current problem ({} when there is none)."""
    return dict(STATE.get("revision") or {})


def stand_down(writer: str) -> bool:
    """Called at the top of a background writer's pass: True while the schema guard reports
    a mismatch, and the pass then writes nothing. Logs when ``writer`` pauses and when it
    resumes - the reason names the two revisions and nothing else."""
    reason = problem()
    with _lock:
        if reason:
            if writer not in _paused:
                _paused.add(writer)
                logger.error("The %s is paused and writes nothing: %s", writer, reason)
            return True
        if writer in _paused:
            _paused.discard(writer)
            logger.warning("The %s resumed: the database schema matches this build again.", writer)
    return False


def reset() -> None:
    """Forget the last answer and which writers are paused, so the next question goes to
    the database (tests, mostly)."""
    with _lock:
        STATE.update({"checked": float("-inf"), "problem": "", "revision": None})
        _paused.clear()
