"""What kind of failure stopped a scan's unit - and so what it may cost (W3.2).

Two kinds, and they are paid for differently:

- **Infrastructure**: the database or its connection pool, the scan's target (the file
  server or endpoint cannot be reached, its session kept resetting), or the disk below
  its floor. Nothing about the unit's files caused it, and it passes. It never spends one
  of the unit's attempts and never marks a scan failed: the runner retries with back-off
  for a bounded time, then pauses the scan, and the resume sweep continues it.
- **Data**: anything else - a file the parser rejects, a folder the account may not list,
  a credential the target refuses. It is the unit's own, so it spends an attempt; a unit
  out of attempts is quarantined and named, and its scan finishes incomplete.

Before this split a two-second database blip spent an attempt of the unit it hit, and if
the "failed" mark landed during the blip the scan was failed for good (roadmap N3).

The decision walks the exception's cause chain: a store error raised from a pool timeout
is the pool timeout. Only an exception's type and a few fixed phrases are read - never a
path or a value from its message.
"""
from __future__ import annotations

import errno
import sqlite3

INFRASTRUCTURE = "infrastructure"
DATA = "data"


class InfrastructureError(RuntimeError):
    """Raised where the product itself knows a failure is not the unit's own."""


class TargetUnreachable(InfrastructureError):
    """The scan's file server or endpoint cannot be reached - its breaker pauses the scan."""


class DiskBelowFloor(InfrastructureError):
    """A volume the scan writes to is below ``DSPM_MIN_FREE_DISK_MB``."""


class DatabaseUnavailable(InfrastructureError):
    """The database could not be reached or did not answer in time."""


_NETWORK_ERRNOS = frozenset(
    code for code in (
        getattr(errno, name, None) for name in (
            "ECONNREFUSED", "ECONNRESET", "ECONNABORTED", "ENETUNREACH", "EHOSTUNREACH", "ETIMEDOUT",
            "ENETDOWN", "EHOSTDOWN", "EPIPE", "ENOTCONN", "ESHUTDOWN",
        )
    ) if code is not None
)
_DISK_ERRNOS = frozenset(code for code in (getattr(errno, "ENOSPC", None), getattr(errno, "EDQUOT", None))
                         if code is not None)
# Windows: the network path was not found (53), the network name is no longer available (64),
# the network name cannot be found (67), the semaphore timeout period expired (121), the
# network location cannot be reached (1231), the remote system is not available (1232), the
# connection was aborted (1236), and the Winsock connection errors; the disk is full (112, 39).
_WINDOWS_NETWORK_ERRORS = frozenset({53, 64, 67, 121, 1222, 1231, 1232, 1236, 10050, 10051, 10052, 10053, 10054,
                                     10057, 10058, 10060, 10061, 10064, 10065})
_WINDOWS_DISK_ERRORS = frozenset({39, 112})
# sqlite3.OperationalError is also what a missing table or a syntax error raises - a bug,
# not a blip - so for it only these phrases mean the database itself was unavailable.
_SQLITE_UNAVAILABLE = ("database is locked", "database table is locked", "busy", "disk i/o error",
                       "unable to open database", "database or disk is full", "interrupted")


def _named(exc: BaseException) -> str:
    kind = type(exc)
    return f"{kind.__module__}.{kind.__qualname__}"


def _transport_types() -> tuple[type, ...]:
    """The SMB and WinRM transports' own connection failures, where those libraries exist."""
    found: list[type] = []
    try:
        from collectors.smb_scanner import _CONNECTION_LOST_TYPES

        found.extend(_CONNECTION_LOST_TYPES)
    except ImportError:  # pragma: no cover - the collector always imports here
        found = []
    try:
        import requests.exceptions as request_errors

        found.extend((request_errors.ConnectionError, request_errors.Timeout))
    except ImportError:  # pragma: no cover - requests is a hard dependency
        return tuple(found)
    return tuple(found)


def _database_types() -> tuple[type, ...]:
    found: list[type] = []
    try:
        import psycopg  # type: ignore

        # OperationalError covers a lost connection, an administrator shutdown, a statement
        # or lock timeout and a full disk; InterfaceError a connection already closed.
        found.extend((psycopg.OperationalError, psycopg.InterfaceError))
    except ImportError:
        return tuple(found)
    try:
        import psycopg_pool  # type: ignore

        found.append(psycopg_pool.PoolTimeout)
        found.append(psycopg_pool.TooManyRequests)
    except ImportError:
        return tuple(found)
    return tuple(found)


_TRANSPORT: tuple[type, ...] | None = None
_DATABASE: tuple[type, ...] | None = None


def _ensure_types() -> None:
    global _TRANSPORT, _DATABASE
    if _DATABASE is None:
        _DATABASE = _database_types()
    if _TRANSPORT is None:
        _TRANSPORT = _transport_types()


def _one_is_infrastructure(exc: BaseException) -> bool:
    _ensure_types()
    if isinstance(exc, InfrastructureError):
        return True
    if _DATABASE and isinstance(exc, _DATABASE):
        return True
    if isinstance(exc, sqlite3.OperationalError):
        text = str(exc).lower()
        return any(phrase in text for phrase in _SQLITE_UNAVAILABLE)
    # The partitioned runner's own name for an SMB session that kept resetting.
    if _named(exc).endswith(("PartitionConnectionLost", "_SmbConnectionLost")):
        return True
    if isinstance(exc, (ConnectionError, TimeoutError)):
        return True
    if _TRANSPORT and isinstance(exc, _TRANSPORT):
        return True
    if isinstance(exc, OSError):
        if exc.errno in _NETWORK_ERRNOS or exc.errno in _DISK_ERRNOS:
            return True
        winerror = getattr(exc, "winerror", None)
        if winerror in _WINDOWS_NETWORK_ERRORS or winerror in _WINDOWS_DISK_ERRORS:
            return True
    return False


def is_infrastructure(exc: BaseException | None) -> bool:
    """Whether ``exc`` - or anything in its cause chain - is an infrastructure failure."""
    seen: set[int] = set()
    depth = 0
    while exc is not None and id(exc) not in seen and depth < 8:
        if _one_is_infrastructure(exc):
            return True
        seen.add(id(exc))
        exc = exc.__cause__ or exc.__context__
        depth += 1
    return False


def kind_of(exc: BaseException) -> str:
    return INFRASTRUCTURE if is_infrastructure(exc) else DATA


def is_target_unreachable(exc: BaseException | None) -> bool:
    """Whether the failure says the scan's target is out of reach (the breaker's case)."""
    _ensure_types()
    seen: set[int] = set()
    while exc is not None and id(exc) not in seen:
        if isinstance(exc, TargetUnreachable):
            return True
        if _DATABASE and isinstance(exc, _DATABASE):
            return False
        if isinstance(exc, (DatabaseUnavailable, DiskBelowFloor, sqlite3.Error)) or _is_disk_full(exc):
            # A full local volume is not the file server: it must not trip the target's
            # breaker, nor tell the operator the target cannot be reached.
            return False
        if _one_is_infrastructure(exc) and not isinstance(exc, InfrastructureError):
            # A network failure that did not come from the database.
            return True
        seen.add(id(exc))
        exc = exc.__cause__ or exc.__context__
    return False


def _is_disk_full(exc: BaseException) -> bool:
    if not isinstance(exc, OSError):
        return False
    return exc.errno in _DISK_ERRNOS or getattr(exc, "winerror", None) in _WINDOWS_DISK_ERRORS


def is_disk_full(exc: BaseException | None) -> bool:
    """Whether ``exc`` - or anything in its cause chain - is a volume out of space."""
    seen: set[int] = set()
    while exc is not None and id(exc) not in seen:
        if _is_disk_full(exc):
            return True
        seen.add(id(exc))
        exc = exc.__cause__ or exc.__context__
    return False


def describe(exc: BaseException) -> str:
    """A short, path-free description: the error's type, and its kind. A volume out of space
    says so, so a pause for it reads as one ("free disk"), not as an outage."""
    if is_disk_full(exc):
        return f"{type(exc).__name__} (infrastructure: free disk exhausted)"
    return f"{type(exc).__name__} ({kind_of(exc)})"
