"""C7: each static gate fails on the defect it exists for.

The gate: "Seeded undefined name, dangerous DOM sink and Python missing import each fail
CI". scripts/static_gate.py is what CI runs; these tests seed each defect into a copy and
require that gate to name it - and require the untouched copy to pass, so a gate that
fails on everything proves nothing either.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from scripts import static_gate

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"


def _semgrep_available() -> bool:
    return bool(os.getenv("SEMGREP_BIN") or shutil.which("semgrep"))


@unittest.skipUnless(shutil.which("node") and (FRONTEND / "node_modules" / "eslint").is_dir(),
                     "the pinned eslint is installed with npm ci in frontend/")
class AnUndefinedNameFailsTheConsoleGateTest(unittest.TestCase):

    def test_a_seeded_undefined_name_fails_and_the_untouched_copy_passes(self) -> None:
        # Beside the real scripts, so the config's import resolves frontend/node_modules.
        with tempfile.TemporaryDirectory(prefix=".gate-seed-", dir=FRONTEND) as tmp:
            seeded = Path(tmp)
            shutil.copyfile(FRONTEND / "eslint.config.mjs", seeded / "eslint.config.mjs")
            shutil.copyfile(FRONTEND / "app.js", seeded / "app.js")
            self.assertEqual(static_gate.gate_eslint(seeded, ["app.js"]), [], "the copy as it is passes")
            with (seeded / "app.js").open("a", encoding="utf-8") as handle:
                handle.write("\nfunction renderSomething() { return renderMissingPanel(); }\n")
            problems = static_gate.gate_eslint(seeded, ["app.js"])
        self.assertTrue(any("no-undef" in problem and "renderMissingPanel" in problem for problem in problems), problems)

    def test_the_console_as_it_is_passes(self) -> None:
        self.assertEqual(static_gate.gate_eslint(), [])


@unittest.skipUnless(importlib.util.find_spec("ruff"), "ruff comes from requirements-static.txt (CI static-analysis job)")
class AMissingImportFailsThePythonGateTest(unittest.TestCase):

    def test_a_seeded_missing_import_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "report_writer.py").write_text("def encode(value):\n    return json.dumps(value)\n",
                                                        encoding="utf-8")
            (Path(tmp) / "clean.py").write_text("import json\n\n\ndef encode(value):\n    return json.dumps(value)\n",
                                                encoding="utf-8")
            seeded = static_gate.gate_ruff(Path(tmp), ["report_writer.py"])
            clean = static_gate.gate_ruff(Path(tmp), ["clean.py"])
        self.assertTrue(any("F821" in problem and "json" in problem for problem in seeded), seeded)
        self.assertEqual(clean, [])

    def test_the_backend_as_it_is_passes(self) -> None:
        self.assertEqual(static_gate.gate_ruff(), [])


@unittest.skipUnless(importlib.util.find_spec("bandit"), "bandit comes from requirements-static.txt (CI static-analysis job)")
class ANewSecurityFindingFailsBanditTest(unittest.TestCase):

    def test_an_unreviewed_finding_fails_and_the_baseline_says_why_for_each(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            package = Path(tmp) / "backend"
            package.mkdir()
            (package / "lookup.py").write_text(
                "def find(conn, name):\n"
                "    return conn.execute(f\"SELECT * FROM users WHERE username = '{name}'\").fetchall()\n",
                encoding="utf-8")
            problems = static_gate.gate_bandit(Path(tmp), ["backend"])
        self.assertTrue(any("B608" in problem and "backend/lookup.py" in problem for problem in problems), problems)
        baseline = json.loads((ROOT / "security" / "bandit-baseline.json").read_text(encoding="utf-8"))
        self.assertTrue(baseline["findings"])
        for entry in baseline["findings"]:
            with self.subTest(entry=entry["file"] + " " + entry["code"][:40]):
                self.assertTrue(entry["reason"].strip() and entry["reviewed"])
                self.assertIn(entry["test_id"], {"B608", "B310"}, "a new kind of finding needs its own review")


class TheRunnerFailsWhenAnyGateFailsTest(unittest.TestCase):
    """CI reads the exit code, so a gate that finds a problem must make it non-zero."""

    def test_one_failing_gate_fails_the_run(self) -> None:
        passing = {name: (lambda: []) for name in static_gate.GATES}
        with unittest.mock.patch.dict(static_gate.GATES, passing):
            self.assertEqual(static_gate.main([]), 0)
            with unittest.mock.patch.dict(static_gate.GATES, {"bandit": lambda: ["backend/x.py: B608 new"]}):
                self.assertEqual(static_gate.main([]), 1)
                self.assertEqual(static_gate.main(["ruff"]), 0, "only the gates asked for run")


@unittest.skipUnless(_semgrep_available(), "semgrep is installed in CI (requirements-semgrep.txt) or named by SEMGREP_BIN")
class ADangerousSinkFailsSemgrepTest(unittest.TestCase):

    def test_each_rule_fails_on_its_seeded_defect_and_not_on_the_safe_form(self) -> None:
        seeded = {
            "sink.js": ('function show(){ document.body.insertAdjacentHTML("beforeend", location.hash); }\n',
                        "js-dangerous-dom-sink"),
            "code.js": ("function run(){ return eval(location.hash); }\n", "js-code-from-string"),
            "handler.js": ('function wire(el){ el.setAttribute("onclick", "go()"); }\n', "js-inline-event-handler"),
            "runner.py": ("import subprocess\n\n\ndef run(command):\n    return subprocess.run(command, shell=True)\n",
                          "py-shell-true"),
            "loader.py": ("import pickle\n\n\ndef load(blob):\n    return pickle.loads(blob)\n",
                          "py-unsafe-deserialization"),
            "calc.py": ("def calc(text):\n    return eval(text)\n", "py-code-from-string"),
            "fetch.py": ("import requests\n\n\ndef get(url):\n    return requests.get(url, verify=False)\n",
                         "py-tls-verification-off"),
        }
        safe = {
            "safe.js": ('function show(el, v){ el.textContent = v; el.setAttribute("title", v);'
                        ' el.addEventListener("click", () => v); }\n'),
            "safe.py": ("import subprocess\nimport json\n\nimport requests\n\n\n"
                        "def run(command, blob, url):\n"
                        "    subprocess.run([command], check=True)\n"
                        "    requests.get(url, timeout=5)\n"
                        "    return json.loads(blob)\n"),
        }
        with tempfile.TemporaryDirectory() as tmp:
            for name, (body, _rule) in seeded.items():
                (Path(tmp) / name).write_text(body, encoding="utf-8")
            for name, body in safe.items():
                (Path(tmp) / name).write_text(body, encoding="utf-8")
            problems = static_gate.gate_semgrep(Path(tmp), [*seeded, *safe])
        for name, (_body, rule) in seeded.items():
            with self.subTest(rule=rule):
                self.assertTrue(any(problem.startswith(name) and problem.endswith(rule) for problem in problems), problems)
        self.assertFalse([problem for problem in problems if problem.startswith("safe")], problems)


if __name__ == "__main__":
    unittest.main()
