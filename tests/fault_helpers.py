"""Functions a worker process runs by name, for the W3.2 fault tests.

A deadline is only proved by a worker that really hangs: patching the parser in the
parent never reaches a child process, which resolves what it runs by name. These sit at
module level so a spawned worker can import them; nothing here runs on import.
"""
from __future__ import annotations

import time


def hang_extracting(data: bytes, extension: str, max_chars: int = 120_000):
    """A parser that never returns, the way a looping object graph keeps pypdf busy."""
    while True:
        time.sleep(0.5)


def quick_extracting(data: bytes, extension: str, max_chars: int = 120_000):
    return data.decode("utf-8", errors="replace")[:max_chars], "", False


def hang_detecting(payload: dict) -> dict:
    """A detector stage that never returns."""
    while True:
        time.sleep(0.5)
