"""Free-space floor for the volumes a scan writes to (WAL/archive workstream, 2026-10).

A scan writes report artifacts on the application host and, on PostgreSQL, rows whose
WAL is written - and, with archiving on, copied - on the database host. When one of those
volumes filled, PostgreSQL stopped (it cannot write WAL) and every scan and click with
it; on this project's test cluster an archive nothing pruned reached 30 GB and left the
system drive with 40 MB.

So a scan does not start, and a running partitioned scan pauses - unfinished, for the
resume sweep to continue - while any watched volume is below ``DSPM_MIN_FREE_DISK_MB``.
Watched: the data directory, the artifact store, and, when they are on this host and
configured, PostgreSQL's data directory (``DSPM_PG_DATA_DIR``) and WAL archive
(``DSPM_WAL_ARCHIVE_DIR``). ``0`` turns the floor off.
"""
from __future__ import annotations

import os
import shutil
import threading
import time
from pathlib import Path

DEFAULT_MIN_FREE_MB = 2048


def min_free_bytes() -> int:
    """``DSPM_MIN_FREE_DISK_MB`` (2 GiB by default; 0 = no floor)."""
    try:
        megabytes = int(os.getenv("DSPM_MIN_FREE_DISK_MB") or DEFAULT_MIN_FREE_MB)
    except ValueError:
        megabytes = DEFAULT_MIN_FREE_MB
    return max(0, megabytes) * 1024 * 1024


def watched_paths() -> list[tuple[str, Path]]:
    """(what it holds, an existing path on its volume) for every volume a scan writes to."""
    from backend import artifacts

    candidates = [
        ("data", os.getenv("DSPM_DATA_DIR") or "data"),
        ("artifacts", str(artifacts.artifact_root())),
        ("postgresql data", os.getenv("DSPM_PG_DATA_DIR") or ""),
        ("wal archive", os.getenv("DSPM_WAL_ARCHIVE_DIR") or ""),
    ]
    watched: list[tuple[str, Path]] = []
    seen: set[Path] = set()
    for label, raw in candidates:
        if not raw.strip():
            continue
        # The volume is what matters; a directory not made yet is measured by its parent.
        probe = Path(raw).resolve()
        while not probe.exists() and probe != probe.parent:
            probe = probe.parent
        if probe.exists() and probe not in seen:
            seen.add(probe)
            watched.append((label, probe))
    return watched


def low_space_reason() -> str | None:
    """Why a scan must not write now - a volume under the floor - or ``None``."""
    floor = min_free_bytes()
    if not floor:
        return None
    for label, path in watched_paths():
        try:
            free = shutil.disk_usage(path).free
        except OSError:
            continue
        if free < floor:
            return (f"free disk on the {label} volume ({path.anchor or path}) is {free // (1024 * 1024)} MB, "
                    f"below the {floor // (1024 * 1024)} MB floor (DSPM_MIN_FREE_DISK_MB)")
    return None


class ThrottledCheck:
    """``low_space_reason`` at most every ``every_seconds``: a partition loop asks often."""

    def __init__(self, every_seconds: float = 10.0) -> None:
        self.every = every_seconds
        self._lock = threading.Lock()
        self._at = float("-inf")
        self._reason: str | None = None

    def __call__(self) -> str | None:
        with self._lock:
            if time.monotonic() - self._at < self.every:
                return self._reason
            self._at = time.monotonic()
        reason = low_space_reason()
        with self._lock:
            self._reason = reason
        return reason
