"""M0/Q3: one supported Python floor, said the same way in three places.

The floor decides which dependency tree exists: `requirements.lock` is generated on it,
CI's lowest leg installs from that lock, and anything older resolves a different tree that
nothing was tested against. The audit found the three disagreeing - `requirements.txt` said
3.10-3.13, the lock was generated on 3.14, and nothing refused an unsupported interpreter -
so these keep the statement, the runtime check and CI in step.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

import main

ROOT = Path(__file__).resolve().parent.parent


class TheSupportedFloorTest(unittest.TestCase):

    def test_an_interpreter_below_the_floor_is_refused_with_the_reason(self) -> None:
        below = (main.MINIMUM_PYTHON[0], main.MINIMUM_PYTHON[1] - 1)
        with self.assertRaises(SystemExit) as refused:
            main.require_supported_python(below)
        message = str(refused.exception)
        self.assertIn(".".join(str(part) for part in main.MINIMUM_PYTHON), message)
        self.assertIn("requirements.lock", message, "the message should say how to get a supported tree")

    def test_the_floor_and_anything_newer_are_accepted(self) -> None:
        for version in (main.MINIMUM_PYTHON, (main.MINIMUM_PYTHON[0], main.MINIMUM_PYTHON[1] + 2)):
            with self.subTest(version=version):
                self.assertIsNone(main.require_supported_python(version))

    def test_the_running_interpreter_is_supported(self) -> None:
        self.assertIsNone(main.require_supported_python(), "the suite is running on an unsupported interpreter")

    def test_the_readme_states_the_same_floor(self) -> None:
        """The first statement a human reads, and the one the Q3 test did not cover:
        the README still said 3.10-3.13 after the floor moved (found in the M0 polish)."""
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        stated = re.findall(r"Python (\d+)\.(\d+) or newer", readme)
        self.assertTrue(stated, "README.md no longer states a supported Python floor")
        for major, minor in stated:
            self.assertEqual((int(major), int(minor)), main.MINIMUM_PYTHON)
        self.assertNotRegex(readme, r"Python 3\.1[01]\s*[-–]\s*3\.1\d",
                            "README.md still advertises a range that predates the floor")

    def test_requirements_documents_the_same_floor(self) -> None:
        header = (ROOT / "requirements.txt").read_text(encoding="utf-8")
        stated = re.search(r"Requires Python (\d+)\.(\d+)", header)
        self.assertIsNotNone(stated, "requirements.txt no longer states a supported Python range")
        self.assertEqual((int(stated.group(1)), int(stated.group(2))), main.MINIMUM_PYTHON)

    def test_ci_tests_the_floor_and_locks_on_it(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        matrix = re.search(r"python-version: \[([^\]]+)\]", workflow)
        self.assertIsNotNone(matrix, "the test matrix is gone")
        versions = [tuple(int(part) for part in item.strip().strip('"').split("."))
                    for item in matrix.group(1).split(",")]
        self.assertEqual(min(versions), main.MINIMUM_PYTHON,
                         "CI's lowest leg must be the floor: it is the leg that installs from the lock")

        drift = re.search(r"lock must be generated on the FLOOR Python.*?python-version: \"(\d+\.\d+)\"",
                          workflow, re.DOTALL)
        self.assertIsNotNone(drift, "the lock-drift job no longer pins a Python version")
        self.assertEqual(tuple(int(part) for part in drift.group(1).split(".")), main.MINIMUM_PYTHON,
                         "the drift gate regenerates the lock on a different version than the floor")


if __name__ == "__main__":
    unittest.main()
