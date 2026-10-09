"""C0.6: files that must never be tracked - run in CI through tests/test_source_tree_hygiene.py.

    python scripts/check_source_tree.py        # exit 1 and a list when the tree holds one

What it refuses, and why:
- editor and merge leftovers (`.bak`, `.orig`, `.rej`, `.swp`, `.tmp`, `~`) - a `store.py.bak`
  of 3,066 lines rode along for weeks, a second copy of the store nobody maintained;
- databases and dumps (`.sqlite`, `.db`, `.dump`, WAL/SHM files) - customer data;
- environment files other than `.env.example` - secrets;
- private keys and certificate stores (`.key`, `.pfx`, `.p12`) - secrets;
- measurement output outside the evidence folders: a benchmark or scan result belongs in
  `docs/database/evidence/` (with the run it came from) or `docs/evidence/`, never at the
  root or beside the code. The retained evidence's owner and location are in
  docs/database/evidence/README.md.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
LEFTOVER_SUFFIXES = (".bak", ".orig", ".rej", ".swp", ".tmp")
DATA_SUFFIXES = (".sqlite", ".sqlite3", ".db", ".dump", ".sqlite-wal", ".sqlite-shm")
SECRET_SUFFIXES = (".key", ".pfx", ".p12")
EVIDENCE_DIRS = ("docs/database/evidence/", "docs/evidence/")
MEASUREMENT_WORDS = ("bench", "benchmark", "result", "results", "soak", "perf", "timing", "measure")
# JSON that is configuration, not output.
ALLOWED_JSON = ("package.json", "package-lock.json", "tsconfig.json", "pins.json", "token-gate-baseline.json",
                "bandit-baseline.json", "launch.json", "manifest.json")


def problems(paths: list[str]) -> list[str]:
    found = []
    for raw in paths:
        path = PurePosixPath(raw.replace("\\", "/"))
        name = path.name.lower()
        text = str(path)
        if name.endswith(LEFTOVER_SUFFIXES) or name.endswith("~"):
            found.append(f"{text}: an editor or merge leftover")
        elif name.endswith(DATA_SUFFIXES):
            found.append(f"{text}: a database or dump")
        elif name == ".env" or (name.startswith(".env.") and name != ".env.example"):
            found.append(f"{text}: an environment file (only .env.example is tracked)")
        elif name.endswith(SECRET_SUFFIXES):
            found.append(f"{text}: a private key or certificate store")
        elif name.endswith(".json") and name not in ALLOWED_JSON and not text.startswith(EVIDENCE_DIRS):
            stem = name[:-len(".json")]
            if len(path.parts) == 1 or any(word in stem for word in MEASUREMENT_WORDS):
                found.append(f"{text}: measurement output outside {' or '.join(EVIDENCE_DIRS)}")
    return found


def tracked_files(root: Path = ROOT) -> list[str]:
    run = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True)
    return [item for item in run.stdout.decode("utf-8", "replace").split("\0") if item]


def main() -> int:
    found = problems(tracked_files())
    for line in found:
        print(line)
    print(f"source tree: {'clean' if not found else f'{len(found)} problem(s)'}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
