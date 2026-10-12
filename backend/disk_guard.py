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


# W4.6: what a scan writes per file it reads (not one it skips), from the measured per-file
# figures - PostgreSQL, pg_scan_rehearsal at 4,000 files (2026-10-08): 25 KiB of tables and
# indexes and 28 KiB of WAL a file, the WAL archived once more where archiving is on; the
# SQLite probe: 12 KiB of database a file; the artifacts and the scan cache about 8 KiB.
# Rounded up, then a quarter again: an estate with more findings a file writes more.
PREFLIGHT_MARGIN = 1.25
_PER_FILE_KIB = {
    "DSPM_PREFLIGHT_DB_KIB_PER_FILE": 32,
    "DSPM_PREFLIGHT_WAL_KIB_PER_FILE": 32,
    "DSPM_PREFLIGHT_LOCAL_KIB_PER_FILE": 8,
}


def _kib(name: str) -> int:
    try:
        return max(0, int(os.getenv(name) or _PER_FILE_KIB[name]))
    except ValueError:
        return _PER_FILE_KIB[name]


def _volume(path: Path) -> str:
    """The volume a path is on: its drive on Windows, its device elsewhere."""
    if path.anchor and os.name == "nt":
        return path.anchor.upper()
    try:
        return str(os.stat(path).st_dev)
    except OSError:
        return str(path.anchor or path)


def projected_bytes(files: int) -> dict[str, int]:
    """What reading ``files`` more files writes, by watched volume label (W4.6)."""
    database = _kib("DSPM_PREFLIGHT_DB_KIB_PER_FILE") * 1024 * files
    wal = _kib("DSPM_PREFLIGHT_WAL_KIB_PER_FILE") * 1024 * files
    local = _kib("DSPM_PREFLIGHT_LOCAL_KIB_PER_FILE") * 1024 * files
    postgres = bool((os.getenv("DSPM_DB_URL") or "").strip())
    return {
        # SQLite keeps its database in the data directory; PostgreSQL's is measured on its
        # data directory when that is on this host and named (DSPM_PG_DATA_DIR).
        "data": 0 if postgres else database,
        "artifacts": local,
        "postgresql data": database + wal if postgres else 0,
        "wal archive": wal if postgres else 0,
    }


def preflight_reason(files: int) -> str | None:
    """Why reading ``files`` more files would not fit (W4.6) - with the numbers - or ``None``.

    Each watched volume must keep the floor (``DSPM_MIN_FREE_DISK_MB``) after what the scan
    is projected to write there: the measured per-file figures, a quarter again. Volumes
    that hold several of what a scan writes are summed. A volume this host cannot see - a
    remote database's - is not projected; the floor still guards what can be seen."""
    floor = min_free_bytes()
    if files <= 0 or not floor:
        return None
    projected = projected_bytes(files)
    need: dict[str, int] = {}
    labels: dict[str, list[str]] = {}
    where: dict[str, Path] = {}
    for label, path in watched_paths():
        cost = int(projected.get(label, 0) * PREFLIGHT_MARGIN)
        if not cost:
            continue
        volume = _volume(path)
        need[volume] = need.get(volume, 0) + cost
        labels.setdefault(volume, []).append(label)
        where.setdefault(volume, path)
    for volume, needed in need.items():
        try:
            free = shutil.disk_usage(where[volume]).free
        except OSError:
            continue
        if free - needed < floor:
            mib = 1024 * 1024
            return (f"the scan is projected to write {needed // mib} MB for the {files} files it has to read "
                    f"({' and '.join(labels[volume])} on {where[volume].anchor or volume}), which would leave "
                    f"{max(0, free - needed) // mib} MB of the {free // mib} MB free there - below the "
                    f"{floor // mib} MB floor (DSPM_MIN_FREE_DISK_MB). Free space, or scan a smaller target.")
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
