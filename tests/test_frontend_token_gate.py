"""The frontend token gate (F0) carries reviewed debt and never reports an unchecked diff clean.

The CI review of M2 found a PR to main would fail with 191 findings: CSS this branch added
while it stayed unmerged (the F0-F4 refit; the sign-in styles C6 moved into login.css).
Those are now a counted baseline, like Bandit's, and anything beyond it still fails. It
also found that a diff which could not run (an unknown base, a shallow clone) was
reported "clean" - it is now exit 2.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import check_frontend_tokens as gate

NEW_IMPORTANT = ("frontend/styles/pages.css", 10, "  .card { margin: 0 !important; }")
NEW_COLOUR = ("frontend/styles/pages.css", 11, "  .card { color: #123456; }")


class TheBaselineCarriesDebtNotNewProblemsTest(unittest.TestCase):

    def _run(self, lines: list, baseline_entries: list | None) -> int:
        with tempfile.TemporaryDirectory() as tmp:
            baseline = Path(tmp) / "baseline.json"
            if baseline_entries is not None:
                baseline.write_text(json.dumps({"entries": baseline_entries}), encoding="utf-8")
            with mock.patch.object(gate, "BASELINE", baseline), \
                    mock.patch.object(gate, "changed_css_lines", return_value=lines), \
                    mock.patch("sys.argv", ["check_frontend_tokens.py", "--base", "origin/main"]):
                return gate.main()

    def test_a_new_problem_fails_without_a_baseline(self) -> None:
        self.assertEqual(self._run([NEW_IMPORTANT], None), 1)

    def test_recorded_debt_passes_and_only_as_many_times_as_recorded(self) -> None:
        entry = {"file": NEW_IMPORTANT[0], "rule": "important", "text": NEW_IMPORTANT[2].strip(), "count": 1}
        self.assertEqual(self._run([NEW_IMPORTANT], [entry]), 0)
        self.assertEqual(self._run([NEW_IMPORTANT, NEW_IMPORTANT], [entry]), 1, "a second copy is new debt")
        self.assertEqual(self._run([NEW_IMPORTANT, NEW_COLOUR], [entry]), 1, "a different problem is new")

    def test_a_baseline_entry_is_bound_to_its_file_and_rule(self) -> None:
        elsewhere = {"file": "frontend/styles/shell.css", "rule": "important", "text": NEW_IMPORTANT[2].strip(),
                     "count": 1}
        self.assertEqual(self._run([NEW_IMPORTANT], [elsewhere]), 1)

    def test_rules_have_stable_ids(self) -> None:
        for line, rule in ((NEW_IMPORTANT, "important"), (NEW_COLOUR, "raw-colour"),
                           (("frontend/x.css", 1, "font-size: 9px;"), "font-size-floor"),
                           (("frontend/x.css", 1, "font-size: 15px;"), "font-size-scale"),
                           (("frontend/x.css", 1, "text-transform: uppercase;"), "uppercase")):
            with self.subTest(rule=rule):
                problems = gate.check_line(*line)
                self.assertTrue(problems)
                self.assertEqual(gate.baseline_key(problems[0], line[2])[1], rule)

    def test_the_committed_baseline_is_well_formed_and_reviewed(self) -> None:
        data = json.loads(gate.BASELINE.read_text(encoding="utf-8"))
        self.assertTrue(data["reviewed"])
        self.assertTrue(data["entries"])
        rule_ids = {rule_id for _marker, rule_id in gate.RULES}
        for entry in data["entries"]:
            with self.subTest(entry=entry["file"] + " " + entry["text"][:40]):
                self.assertTrue(entry["file"].startswith("frontend/") and entry["file"].endswith(".css"))
                self.assertIn(entry["rule"], rule_ids)
                self.assertGreaterEqual(entry["count"], 1)


class ADiffThatCannotRunIsNotCleanTest(unittest.TestCase):

    def test_an_unknown_base_exits_2(self) -> None:
        with self.assertRaises(SystemExit) as stopped:
            gate.changed_css_lines("no-such-ref-for-the-token-gate")
        self.assertEqual(stopped.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
