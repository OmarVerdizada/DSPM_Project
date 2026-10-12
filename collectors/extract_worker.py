"""A deadline on a document's text extraction, in a process that can be killed (W3.2).

Parsing a hostile or broken document - a PDF whose object graph loops, an Office file
whose XML never ends - was the one piece of a scan that could run for ever: it ran in the
collector's own thread, deadlines were only checked between files, and a thread cannot be
stopped. Its scan then stayed RUNNING for ever (roadmap N5).

Extraction now runs in a small pool of worker processes. A document that has not been
extracted within ``DSPM_FILE_DEADLINE_SECONDS`` (120 s) has its worker killed - which
stops the work - and the file is marked FAILED with the reason; a fresh worker takes the
next document. The parent's extraction limits (``binary_extractor.MAX_DOC_*``) travel with
every request, so a worker extracts exactly as the parent would. ``0`` extracts in-process,
as before, with no deadline.

The text and the file's SHA-256 still come from one read (W2.2): the parent read the bytes
and hashes them; only the parse crosses the process boundary.
"""
from __future__ import annotations

import atexit
import importlib
import logging
import multiprocessing
import os
import threading
import time

from collectors import binary_extractor

logger = logging.getLogger(__name__)

DEFAULT_DEADLINE_SECONDS = 120
DEADLINE_EXCEEDED = "deadline_exceeded"
# What a worker runs, by name - so a test can name a parser that never returns and watch
# the deadline stop it in a real worker process.
EXTRACT_TARGET = "collectors.binary_extractor:extract_binary_bytes_detail"
# The extractor's limits a worker must apply exactly as the parent has them.
_LIMITS = ("MAX_DOC_ENTRY_BYTES", "MAX_DOC_TOTAL_BYTES", "MAX_DOC_COMPRESSION_RATIO", "MAX_DOC_PARTS")


def deadline_seconds() -> int:
    """``DSPM_FILE_DEADLINE_SECONDS``: how long one document's extraction may run (0 = no
    deadline, in-process)."""
    try:
        return max(0, min(int(os.getenv("DSPM_FILE_DEADLINE_SECONDS") or DEFAULT_DEADLINE_SECONDS), 3600))
    except ValueError:
        return DEFAULT_DEADLINE_SECONDS


def _limits() -> dict:
    return {name: getattr(binary_extractor, name) for name in _LIMITS if hasattr(binary_extractor, name)}


def exit_with_parent(poll_seconds: float = 2.0) -> None:
    """In a worker process: end it once its parent is gone (W3.2).

    A parent that is killed - not shut down - never closes the worker's pipe while the
    worker is inside a call, so a worker held by a hung parser would stay for ever. A
    daemon thread watches the parent and exits the process when it is gone. It cannot
    help while native code holds the interpreter lock; a parser looping in Python, or one
    waiting, is ended."""
    parent = multiprocessing.parent_process()
    if parent is None:
        return

    def watch() -> None:
        while parent.is_alive():
            time.sleep(poll_seconds)
        os._exit(1)

    threading.Thread(target=watch, name="dspm-parent-watch", daemon=True).start()


def _serve(conn) -> None:
    """A worker: extract what it is sent until its pipe closes."""
    exit_with_parent()
    while True:
        try:
            request = conn.recv()
        except (EOFError, OSError):
            return
        if request is None:
            return
        data, extension, max_chars, limits, target = request
        for name, value in limits.items():
            setattr(binary_extractor, name, value)
        try:
            module, _, function = str(target).partition(":")
            extract = getattr(importlib.import_module(module), function)
            conn.send(("ok", extract(data, extension, max_chars)))
        except BaseException as exc:  # noqa: BLE001 - every failure goes back as its type
            conn.send(("error", type(exc).__name__))


class _Worker:
    def __init__(self) -> None:
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe()
        self.process = context.Process(target=_serve, args=(child,), name="dspm-extract", daemon=True)
        self.process.start()
        child.close()
        self.conn = parent

    def kill(self) -> None:
        try:
            self.process.kill()
            self.process.join(timeout=5)
        except Exception:  # noqa: BLE001 - a worker already gone is the goal
            logger.debug("extraction worker already gone")
        try:
            self.conn.close()
        except OSError:
            logger.debug("extraction pipe already closed")

    def close(self) -> None:
        try:
            self.conn.send(None)
        except OSError:
            logger.debug("extraction worker already gone")
        self.process.join(timeout=2)
        if self.process.is_alive():
            self.kill()


class _Pool:
    """Up to ``size`` workers, started when first needed and reused; a killed one is replaced."""

    def __init__(self, size: int) -> None:
        self._slots = threading.BoundedSemaphore(size)
        self._lock = threading.Lock()
        self._idle: list[_Worker] = []
        self._all: list[_Worker] = []
        self.killed = 0

    def run(self, data: bytes, extension: str, max_chars: int, deadline: float) -> tuple[str, str, bool]:
        with self._slots:
            with self._lock:
                worker = self._idle.pop() if self._idle else None
            if worker is None or not worker.process.is_alive():
                worker = _Worker()
                with self._lock:
                    self._all.append(worker)
            try:
                worker.conn.send((data, extension, max_chars, _limits(), EXTRACT_TARGET))
                if not worker.conn.poll(deadline):
                    worker.kill()
                    with self._lock:
                        self._all.remove(worker)
                        self.killed += 1
                    return "", DEADLINE_EXCEEDED, False
                status, value = worker.conn.recv()
            except (EOFError, OSError, BrokenPipeError):
                # The worker died under the document (it crashed the parser): a failed extraction.
                worker.kill()
                with self._lock:
                    if worker in self._all:
                        self._all.remove(worker)
                return "", "not_extracted", False
            with self._lock:
                self._idle.append(worker)
            if status != "ok":
                return "", "not_extracted", False
            text, reason, truncated = value
            return text, reason, bool(truncated)

    def close(self) -> None:
        with self._lock:
            workers, self._all, self._idle = list(self._all), [], []
        for worker in workers:
            worker.close()


_pool: _Pool | None = None
_pool_lock = threading.Lock()


def _the_pool() -> _Pool:
    global _pool
    with _pool_lock:
        if _pool is None:
            _pool = _Pool(max(1, min(4, (os.cpu_count() or 2) - 1)))
        return _pool


def shutdown() -> None:
    """Stop the workers (tests, and a process on its way out)."""
    global _pool
    with _pool_lock:
        pool, _pool = _pool, None
    if pool is not None:
        pool.close()


atexit.register(shutdown)


def killed_workers() -> int:
    pool = _pool
    return pool.killed if pool is not None else 0


def extract_bytes_detail(data: bytes, extension: str, max_chars: int = 120_000) -> tuple[str, str, bool]:
    """``binary_extractor.extract_binary_bytes_detail`` under the per-file deadline.

    Returns ``(text, reason, truncated)``; ``reason`` is ``"deadline_exceeded"`` when the
    deadline stopped the extraction - the caller marks the file FAILED with that reason.
    """
    deadline = deadline_seconds()
    if deadline <= 0:
        return binary_extractor.extract_binary_bytes_detail(data, extension, max_chars)
    return _the_pool().run(data, extension, max_chars, float(deadline))
