"""C7: the static gates, run the same way on a laptop, in CI and by the tests that seed them.

    python scripts/static_gate.py            # every gate
    python scripts/static_gate.py bandit     # one of: ruff, mypy, bandit, semgrep, eslint

Exit 0 when every gate passes. Each gate is aimed at a defect that shipped or could ship:
- ruff:    a name used and never defined or imported (E9, F63, F7, F82) - the Python
           counterpart of the console's no-undef;
- mypy:    the security modules' types (deployment boundary, client address, scan scope,
           SIEM settings, permissions, error disclosure, audit chain);
- bandit:  medium-severity findings not in the reviewed baseline (security/bandit-baseline.json,
           matched by file, test and code - not line - so edits elsewhere do not disturb it);
- semgrep: the rules in security/semgrep.yml (dangerous DOM sinks, code from strings, shell,
           unsafe deserialization, TLS verification off), run offline;
- eslint:  no-undef over frontend/*.js with the pinned local install.
Tools are the pinned ones: ruff/mypy/bandit/semgrep from the environment (SEMGREP_BIN may name
a semgrep outside it), eslint from frontend/node_modules.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYTHON_TREES = ["backend", "classification", "collectors", "discovery", "risk", "scripts", "permissions", "main.py"]
BANDIT_TREES = ["backend", "classification", "collectors", "discovery", "risk", "permissions", "main.py"]
MYPY_MODULES = [
    "backend/deployment_boundary.py", "backend/client_address.py", "backend/target_scope.py",
    "backend/siem_settings.py", "backend/permissions.py", "backend/errors.py", "backend/audit_chain.py",
]
FRONTEND_SCRIPTS = sorted([path.name for path in (ROOT / "frontend").glob("*.js")]
                          + [f"console/{path.name}" for path in (ROOT / "frontend" / "console").glob("*.js")])


def _run(command: list[str], cwd: Path = ROOT) -> subprocess.CompletedProcess:
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace")


def _tool(name: str) -> str | None:
    if name == "semgrep" and os.getenv("SEMGREP_BIN"):
        return os.environ["SEMGREP_BIN"]
    return shutil.which(name)


def gate_ruff(root: Path = ROOT, targets: list[str] | None = None) -> list[str]:
    run = _run([sys.executable, "-m", "ruff", "check", "--select", "E9,F63,F7,F82", "--output-format", "concise",
                *(targets or PYTHON_TREES)], cwd=root)
    return [] if run.returncode == 0 else [line for line in run.stdout.splitlines() if line.strip()] or [run.stderr.strip()]


def gate_mypy(root: Path = ROOT, targets: list[str] | None = None) -> list[str]:
    run = _run([sys.executable, "-m", "mypy", "--ignore-missing-imports", "--follow-imports=silent",
                "--no-error-summary", *(targets or MYPY_MODULES)], cwd=root)
    return [] if run.returncode == 0 else [line for line in run.stdout.splitlines() if line.strip()] or [run.stderr.strip()]


def bandit_key(file: str, test_id: str, code: str) -> tuple[str, str, str]:
    lines = []
    for line in code.strip().splitlines():
        body = re.sub(r"^\d+\s?", "", line).strip()
        if body:
            lines.append(body)
    return file.replace("\\", "/"), test_id, " ".join(lines)


def gate_bandit(root: Path = ROOT, targets: list[str] | None = None) -> list[str]:
    run = _run([sys.executable, "-m", "bandit", "-q", "-r", *(targets or BANDIT_TREES), "-ll", "-f", "json"], cwd=root)
    try:
        report = json.loads(run.stdout)
    except ValueError:
        return [f"bandit did not report: {run.stderr.strip()[:300]}"]
    baseline = json.loads((ROOT / "security" / "bandit-baseline.json").read_text(encoding="utf-8"))
    allowed = Counter((item["file"], item["test_id"], item["code"]) for item in baseline["findings"])
    found = Counter(bandit_key(item["filename"], item["test_id"], item["code"]) for item in report["results"])
    new = found - allowed
    return [f"{file}: {test_id} not in the reviewed baseline: {code[:160]}" for (file, test_id, code), _n in new.items()]


def gate_semgrep(root: Path = ROOT, targets: list[str] | None = None) -> list[str]:
    semgrep = _tool("semgrep")
    if not semgrep:
        return ["semgrep is not installed (pip install semgrep, or set SEMGREP_BIN)"]
    targets = targets or [*PYTHON_TREES, *(f"frontend/{name}" for name in FRONTEND_SCRIPTS)]
    run = _run([semgrep, "--config", str(ROOT / "security" / "semgrep.yml"), "--metrics=off", "--disable-version-check", "--quiet",
                "--json", "--timeout", "300", "--timeout-threshold", "0", "--max-target-bytes", "5000000", *targets],
               cwd=root)
    try:
        report = json.loads(run.stdout)
    except ValueError:
        return [f"semgrep did not report: {run.stderr.strip()[:300]}"]
    problems = [f"{item['path']}:{item['start']['line']}: {item['check_id'].split('.')[-1]}" for item in report["results"]]
    problems += [f"semgrep error: {error.get('message', '')[:200]}" for error in report.get("errors", [])]
    return problems


def gate_eslint(root: Path = ROOT, targets: list[str] | None = None) -> list[str]:
    """`root` is the directory holding eslint.config.mjs and the scripts (frontend/, or a
    seeded copy beside it that still resolves frontend/node_modules)."""
    frontend = root / "frontend" if (root / "frontend").is_dir() else root
    local = ROOT / "frontend" / "node_modules" / "eslint" / "bin" / "eslint.js"
    node = shutil.which("node")
    if not local.is_file() or not node:
        return ["eslint is not installed in frontend/node_modules (npm ci in frontend/)"]
    run = _run([node, str(local), "--format", "json", *(targets or FRONTEND_SCRIPTS)], cwd=frontend)
    try:
        report = json.loads(run.stdout)
    except ValueError:
        return [f"eslint did not report: {run.stderr.strip()[:300]}"]
    return [f"frontend/{Path(item['filePath']).relative_to(frontend.resolve()).as_posix() if Path(item['filePath']).is_relative_to(frontend.resolve()) else Path(item['filePath']).name}"
            f":{message['line']}: {message.get('ruleId')}: {message['message']}"
            for item in report for message in item["messages"]]


GATES = {"ruff": gate_ruff, "mypy": gate_mypy, "bandit": gate_bandit, "semgrep": gate_semgrep, "eslint": gate_eslint}


def main(argv: list[str]) -> int:
    chosen = argv or list(GATES)
    failed = False
    for name in chosen:
        problems = GATES[name]()
        print(f"{name}: {'ok' if not problems else f'{len(problems)} problem(s)'}")
        for problem in problems:
            print(f"  {problem}")
        failed = failed or bool(problems)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
