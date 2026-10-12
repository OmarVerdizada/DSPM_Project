"""Hard, cross-platform timeout for CPU-bound work (roadmap 1.2).

A catastrophic-backtracking regex holds the CPython GIL inside a single C call,
so NO thread-based timeout can interrupt it (even ``future.result(timeout)``
never fires - the waiting thread cannot get the GIL back). The only portable way
to enforce a hard CPU budget is to run the work in a separate PROCESS and kill it
on timeout.

Process spawn is not free, so this is used only for BOUNDED, RARE operations -
validating catalog regexes at import time (admin-gated) - never per-scanned-file.
It replaces the deleted complexity heuristic (0.5) with a REAL check: a pattern
is rejected only if it actually backtracks catastrophically on adversarial input.
"""
from __future__ import annotations

import multiprocessing as mp
import re
from typing import Any, Callable

# Inputs crafted to trigger common catastrophic backtracking (nested/overlapping
# quantifiers, alternation) - a non-matching suffix forces maximal backtracking.
_PROBE_INPUTS = (
    "a" * 96 + "!",
    "0" * 96 + "!",
    "ab" * 64 + "!",
    "-" * 96 + "X",
    "A1" * 64 + "!",
)


def _worker(fn, args, kwargs, queue) -> None:  # pragma: no cover - runs in child
    try:
        queue.put(("ok", fn(*args, **kwargs)))
    except BaseException as exc:  # noqa: BLE001 - report anything back to the parent
        queue.put(("err", repr(exc)))


def run_with_hard_timeout(fn: Callable[..., Any], *args: Any, timeout: float, **kwargs: Any) -> Any:
    """Run ``fn(*args, **kwargs)`` in a separate (spawned) process and KILL it if
    it exceeds ``timeout`` seconds, raising ``TimeoutError``. ``fn`` and its args
    must be picklable (a module-level function, simple args). Worker exceptions
    surface as ``RuntimeError``."""
    ctx = mp.get_context("spawn")  # spawn: consistent behavior + Windows-safe
    queue = ctx.Queue()
    proc = ctx.Process(target=_worker, args=(fn, args, kwargs, queue), daemon=True)
    proc.start()
    proc.join(timeout)
    if proc.is_alive():
        proc.terminate()
        proc.join(5)
        if proc.is_alive():  # pragma: no cover - last resort
            proc.kill()
            proc.join()
        raise TimeoutError(f"operation exceeded {timeout}s and was killed")
    try:
        status, payload = queue.get_nowait()
    except Exception as exc:  # pragma: no cover - defensive
        raise RuntimeError("preemptible worker produced no result") from exc
    if status == "err":
        raise RuntimeError(payload)
    return payload


def _run_patterns(patterns: list[tuple[str, int]]) -> bool:  # runs in the child
    for raw, flags in patterns:
        compiled = re.compile(raw, flags)
        for probe in _PROBE_INPUTS:
            compiled.search(probe)
    return True


def catastrophic_regexes(
    patterns: list[tuple[str, int]],
    *,
    batch_timeout: float = 5.0,
    per_pattern_timeout: float = 3.0,
) -> list[str]:
    """Return the raw patterns that backtrack catastrophically on adversarial
    input, proven by running them under a hard process-timeout.

    Fast path: one subprocess probes all patterns together. Only if that trips do
    we probe per-pattern (a rare, already-being-rejected catalog) to name the
    offenders. Compile errors are ignored here - they are caught separately by the
    per-pattern length/compile check.

    Timeouts are generous because process spawn itself costs ~1s (Windows) - they
    must sit well above spawn+import so a SAFE pattern completes in time; a
    catastrophic one runs forever and is killed at the budget regardless.
    """
    candidates = [(raw, flags) for raw, flags in patterns if raw]
    if not candidates:
        return []
    try:
        run_with_hard_timeout(_run_patterns, candidates, timeout=batch_timeout)
        return []
    except TimeoutError:
        pass
    except RuntimeError:
        pass  # a compile error in the batch - fall through to per-pattern
    bad: list[str] = []
    for raw, flags in candidates:
        try:
            run_with_hard_timeout(_run_patterns, [(raw, flags)], timeout=per_pattern_timeout)
        except TimeoutError:
            bad.append(raw)
        except RuntimeError:
            pass
    return bad
