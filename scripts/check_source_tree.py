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

import os
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
                "bandit-baseline.json", "launch.json", "manifest.json",
                "build.json")


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
    """`git ls-files` in a checkout; in a copy without git metadata (a handover export or an
    unpacked release), every file outside the folders an install creates beside the code."""
    if not (root / ".git").exists():
        return _files_in_copy(root)
    run = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True)
    return [item for item in run.stdout.decode("utf-8", "replace").split("\0") if item]


# What scripts/setup.ps1, the tools and a running install create beside the code.
NOT_SOURCE = {".git", ".venv", "venv", "__pycache__", "node_modules", ".pytest_cache", ".mypy_cache",
              ".ruff_cache", ".semgrep-venv"}
# ... and the generated demo corpora .gitignore names (tests regenerate them at the root).
NOT_SOURCE_AT_ROOT = {"data", "tmp", "dist", "enterprise_test_data", "enterprise_test_data_repro"}


def _files_in_copy(root: Path) -> list[str]:
    found: list[str] = []
    for folder, dirs, files in os.walk(root):
        relative = Path(folder).relative_to(root)
        at_root = relative == Path(".")
        dirs[:] = sorted(d for d in dirs if d not in NOT_SOURCE and not (at_root and d in NOT_SOURCE_AT_ROOT))
        found.extend((relative / name).as_posix() for name in sorted(files))
    return found


def main() -> int:
    found = problems(tracked_files())
    for line in found:
        print(line)
    print(f"source tree: {'clean' if not found else f'{len(found)} problem(s)'}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
