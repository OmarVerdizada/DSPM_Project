"""A detector pool whose workers die while warming, run in a process of its own.

`tests/test_detector_pool_worker_death.py` runs this file and requires it to exit. Before
the fix it could not: the warm-up callback asked the executor to shut down while CPython's
manager thread held the executor's lock to fail that very future, so the process hung at
exit with its work already done.

It has to be a real process because the failure only exists between real processes, and a
file rather than `-c` because Windows re-imports `__main__` in every spawned worker - which
is also why everything here sits behind the `__main__` guard.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def die_on_warm_up() -> bool:
    """Warm-up that kills its worker outright, the way an OOM kill or antivirus would.

    Submitted by reference, so the worker resolves and runs this function - patching
    `warm_up` in the parent alone would never reach the child.
    """
    os._exit(70)


def main() -> int:
    from discovery import detector_pool

    detector_pool.warm_up = die_on_warm_up
    pool = detector_pool.DetectorPool(workers=2)
    pool.start()

    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and not pool.diagnostics()["disabled_reason"]:
        time.sleep(0.1)

    diagnostics = pool.diagnostics()
    result = {
        "disabled_reason": diagnostics["disabled_reason"],
        "enabled": diagnostics["enabled"],
        "fell_back_in_process": pool.run({"payload": "irrelevant, the pool is gone"}) is None,
        "files_in_process": pool.diagnostics()["files_in_process"],
    }
    # What the engine does in its own `finally`; it must be safe after a broken pool.
    pool.shutdown()
    print(json.dumps(result), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
