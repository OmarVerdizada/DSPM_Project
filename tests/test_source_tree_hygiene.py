"""C0.6: the source tree holds source - no leftovers, data, secrets or stray measurement output.

The check runs over `git ls-files` on every CI run (this file is part of `python -m pytest`),
so a seeded `.bak`, database, `.env` or benchmark JSON at the root fails the build. The
retained evidence has an owner and a place: docs/database/evidence/README.md.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_source_tree  # noqa: E402


class TheTrackedTreeTest(unittest.TestCase):
    def test_the_repository_is_clean(self) -> None:
        self.assertEqual(check_source_tree.problems(check_source_tree.tracked_files()), [])

    def test_seeded_unwanted_files_are_refused(self) -> None:
        seeded = ["backend/store.py.bak", "frontend/app.js.orig", "collectors/x.py.rej", "notes.txt~",
                  "data/dspm.sqlite", "backup.dump", "data/dspm.sqlite-wal", ".env", ".env.production",
                  "certs/server.key", "certs/server.pfx", "results.json", "bench_scan.json",
                  "scripts/perf_results_2026.json", "tmp/scan.tmp", "scan_output.json"]
        found = check_source_tree.problems(seeded)
        self.assertEqual(len(found), len(seeded), found)

    def test_what_belongs_is_allowed(self) -> None:
        kept = [".env.example", "frontend/package.json", "frontend/package-lock.json", "packaging/windows/pins.json",
                "security/bandit-baseline.json", "backend/compliance_profiles.json",
                "docs/database/evidence/capacity_soak_20260903T055000Z.json",
                "docs/evidence/c14-bounded-2026-09-28.json", "docs/database/P7_CERTIFICATION_PROFILE.json",
                "README.md", "main.py"]
        self.assertEqual(check_source_tree.problems(kept), [])

    def test_the_retained_evidence_has_an_owner_and_a_place(self) -> None:
        readme = (ROOT / "docs" / "database" / "evidence" / "README.md").read_text(encoding="utf-8")
        self.assertIn("**Owner:**", readme)
        self.assertIn("docs/evidence/", readme)


if __name__ == "__main__":
    unittest.main()
