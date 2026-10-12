"""What an SMB scan may ask of the server it reads (scaling roadmap W2.3).

A scan used to be bounded only by its own worker count (up to 64) and a per-process I/O
budget: nothing kept it from opening as many sessions to one file server as it had
workers, reading as fast as the wire allowed in business hours, retrying a struggling
server at once, or recalling a tiered file from tape by reading it. Per server, now:

- ``DSPM_SMB_MAX_SESSIONS_PER_TARGET`` (8): sessions open to it at once, across every
  scan of this process. A worker waits for one.
- ``DSPM_SMB_MAX_MBPS`` (0 = no cap): content bytes per second read from it, shared by
  every reader - a token bucket with a quarter second of burst.
- Backoff: a lost session doubles the pause before the next one is opened (1 s up to
  60 s); sessions that complete halve it again.
- Offline and recall-on-access files (FILE_ATTRIBUTE_OFFLINE, RECALL_ON_OPEN,
  RECALL_ON_DATA_ACCESS) are not read unless ``DSPM_SMB_READ_OFFLINE=1``: reading one
  makes the storage tier bring it back. Their record says so (SKIPPED_POLICY).

What it cost is counted per server - bytes, reads, waits, losses, offline files skipped -
and reported in the scan's diagnostics.
"""
from __future__ import annotations

import os
import threading
import time
from contextlib import contextmanager

FILE_ATTRIBUTE_OFFLINE = 0x1000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000
_RECALL_ATTRIBUTES = FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS

DEFAULT_MAX_SESSIONS = 8
BACKOFF_FIRST_SECONDS = 1.0
BACKOFF_MAX_SECONDS = 60.0


def _env_number(name: str, default: float, minimum: float) -> float:
    try:
        return max(minimum, float(os.getenv(name) or default))
    except ValueError:
        return default


def max_sessions_per_target() -> int:
    return int(_env_number("DSPM_SMB_MAX_SESSIONS_PER_TARGET", DEFAULT_MAX_SESSIONS, 1))


def max_bytes_per_second() -> float:
    """``DSPM_SMB_MAX_MBPS`` in bytes a second; 0 is no cap."""
    return _env_number("DSPM_SMB_MAX_MBPS", 0, 0) * 1024 * 1024


def read_offline_files() -> bool:
    return str(os.getenv("DSPM_SMB_READ_OFFLINE") or "").strip().lower() in {"1", "true", "yes", "on"}


def needs_recall(file_attributes) -> bool:
    """Whether reading this file's content would make tiered storage recall it."""
    try:
        return bool(int(file_attributes or 0) & _RECALL_ATTRIBUTES)
    except (TypeError, ValueError):
        return False


class TokenBucket:
    """Bytes a second, with a quarter second of burst. ``clock``/``sleep`` are for tests."""

    def __init__(self, rate: float, *, clock=time.monotonic, sleep=time.sleep) -> None:
        self.rate = float(rate)
        self.capacity = max(64 * 1024.0, self.rate / 4)
        self._tokens = self.capacity
        self._clock, self._sleep = clock, sleep
        self._at = clock()
        self._lock = threading.Lock()

    def take(self, amount: int) -> float:
        """Take ``amount`` bytes, waiting while the bucket is short; returns seconds waited."""
        if self.rate <= 0 or amount <= 0:
            return 0.0
        with self._lock:
            now = self._clock()
            self._tokens = min(self.capacity, self._tokens + (now - self._at) * self.rate)
            self._at = now
            self._tokens -= amount
            wait = -self._tokens / self.rate if self._tokens < 0 else 0.0
        if wait > 0:
            self._sleep(wait)
        return wait


class TargetGate:
    """One SMB server's sessions, bandwidth, backoff and counters, shared by every scan here."""

    def __init__(self, server: str, *, sessions: int, bytes_per_second: float,
                 clock=time.monotonic, sleep=time.sleep) -> None:
        self.server = server
        self.sessions = max(1, int(sessions))
        self._slots = threading.BoundedSemaphore(self.sessions)
        self._bucket = TokenBucket(bytes_per_second, clock=clock, sleep=sleep)
        self._clock, self._sleep = clock, sleep
        self._lock = threading.Lock()
        self._backoff = 0.0
        self._open = 0
        self.counters = {"bytes_read": 0, "reads": 0, "throttle_wait_ms": 0, "session_wait_ms": 0,
                         "backoff_wait_ms": 0, "sessions_lost": 0, "sessions_peak": 0, "offline_skipped": 0}

    @contextmanager
    def session(self):
        """Hold one of the server's sessions; waits for a free one and for any backoff."""
        started = self._clock()
        self._slots.acquire()
        waited = self._clock() - started
        try:
            with self._lock:
                pause = self._backoff
                self._open += 1
                self.counters["sessions_peak"] = max(self.counters["sessions_peak"], self._open)
                self.counters["session_wait_ms"] += int(waited * 1000)
            if pause > 0:
                self._sleep(pause)
                with self._lock:
                    self.counters["backoff_wait_ms"] += int(pause * 1000)
            yield
        finally:
            with self._lock:
                self._open -= 1
            self._slots.release()

    def read(self, amount: int) -> None:
        """Count ``amount`` content bytes read, and hold the reader to the bandwidth cap."""
        waited = self._bucket.take(amount)
        with self._lock:
            self.counters["bytes_read"] += int(amount)
            self.counters["reads"] += 1
            self.counters["throttle_wait_ms"] += int(waited * 1000)

    def lost(self) -> None:
        """A session to the server was lost: the next one waits longer."""
        with self._lock:
            self.counters["sessions_lost"] += 1
            self._backoff = min(BACKOFF_MAX_SECONDS, max(BACKOFF_FIRST_SECONDS, self._backoff * 2))

    def completed(self) -> None:
        with self._lock:
            self._backoff = self._backoff / 2 if self._backoff >= BACKOFF_FIRST_SECONDS * 2 else 0.0

    def skipped_offline(self) -> None:
        with self._lock:
            self.counters["offline_skipped"] += 1

    @property
    def backoff_seconds(self) -> float:
        with self._lock:
            return self._backoff

    def snapshot(self) -> dict:
        with self._lock:
            return {"server": self.server, "max_sessions": self.sessions,
                    "max_bytes_per_second": int(self._bucket.rate), "backoff_seconds": round(self._backoff, 3),
                    **self.counters}


_gates: dict[str, TargetGate] = {}
_gates_lock = threading.Lock()


def target_gate(server: str) -> TargetGate:
    """The process's gate for ``server`` (case-insensitive), sized from the environment when first asked."""
    key = str(server or "").strip().lower()
    with _gates_lock:
        gate = _gates.get(key)
        if gate is None:
            gate = _gates[key] = TargetGate(key, sessions=max_sessions_per_target(),
                                            bytes_per_second=max_bytes_per_second())
        return gate


def reset_target_gates() -> None:
    """Forget every gate (tests, and a change of configuration)."""
    with _gates_lock:
        _gates.clear()
