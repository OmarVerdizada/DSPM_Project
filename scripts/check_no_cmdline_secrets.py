#!/usr/bin/env python3
"""H1 recurrence guard (security remediation roadmap, Phase 0.2).

Invariant enforced: a credential must NEVER reach a subprocess command line. It
must be handed to the child process through its environment block (``env=...``)
and read as ``$env:NAME`` inside any PowerShell script. Command lines are visible
to Windows 4688 / Sysmon EID 1 auditing and are routinely shipped to a SIEM;
environment blocks are not captured by command-line auditing.

This is a static, dependency-free check (stdlib ``ast`` only) meant to run as a
blocking CI step. It FAILS the build if, under ``collectors/`` or ``backend/``,
it finds:

  Rule 1  A subprocess exec call whose COMMAND argument (the positional command
          list/string) interpolates a credential. The ``env=`` keyword is exempt
          - that is the correct channel.
  Rule 2  A PowerShell literal that reads the credential from the serialized
          payload instead of the environment (``$payload.password`` etc.) - the
          exact shape of the original H1 bug.
  Rule 3  (collectors/ only) A dict literal with a credential key
          (``{"password": ...}``), which in the collectors is invariably a
          credential being packaged into a base64 payload that lands on a
          command line.

Limitation: dataflow into an already-built script *variable* cannot be proven
statically. The unit tests in ``tests/test_winrm_smb_hardening.py`` assert the
*actual* argv of the WinRM-activation and SMB-ACL sinks carries no secret and
complement this gate.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCAN_DIRS = ("collectors", "backend")
EXEC_ATTRS = {"run", "Popen", "call", "check_call", "check_output"}
SECRET_NAMES = {"password", "passwd", "pw", "secret"}
FORBIDDEN_PS = ("$payload.password", "$payload.passwd", "$payload.pw", "$payload.secret")


def _subtree_refs_secret(node: ast.AST) -> bool:
    """True if `node`'s subtree references a credential by name/attribute."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute) and sub.attr.lower() in SECRET_NAMES:
            return True
        if isinstance(sub, ast.Name) and sub.id.lower() in SECRET_NAMES:
            return True
    return False


def _is_subprocess_exec(call: ast.Call) -> bool:
    func = call.func
    return isinstance(func, ast.Attribute) and func.attr in EXEC_ATTRS


def _check_ast(path: Path, src: str, in_collectors: bool) -> list[str]:
    problems: list[str] = []
    try:
        tree = ast.parse(src)
    except SyntaxError as exc:  # pragma: no cover - a syntax error fails elsewhere
        return [f"{path}:{exc.lineno}: could not parse ({exc.msg})"]
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_subprocess_exec(node) and node.args:
            if _subtree_refs_secret(node.args[0]):
                problems.append(
                    f"{path}:{node.lineno}: Rule 1 - subprocess command interpolates a credential; "
                    "pass it via env= and read $env:NAME in the script instead"
                )
        if in_collectors and isinstance(node, ast.Dict):
            for key in node.keys:
                if isinstance(key, ast.Constant) and isinstance(key.value, str) and key.value.lower() in SECRET_NAMES:
                    problems.append(
                        f"{path}:{node.lineno}: Rule 3 - dict packages a credential ({key.value!r} key); "
                        "in collectors this reaches a command line - pass the secret via env= instead"
                    )
    return problems


def _check_text(path: Path, src: str) -> list[str]:
    problems: list[str] = []
    for pat in FORBIDDEN_PS:
        idx = src.find(pat)
        if idx != -1:
            line = src[:idx].count("\n") + 1
            problems.append(
                f"{path}:{line}: Rule 2 - PowerShell reads the credential from the payload ({pat}); "
                "read it from an environment variable ($env:NAME) instead"
            )
    return problems


def check_source(rel_path: Path, src: str, in_collectors: bool) -> list[str]:
    return _check_ast(rel_path, src, in_collectors) + _check_text(rel_path, src)


def main() -> int:
    problems: list[str] = []
    for directory in SCAN_DIRS:
        base = ROOT / directory
        if not base.exists():
            continue
        in_collectors = directory == "collectors"
        for path in sorted(base.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            # utf-8-sig strips a leading BOM (some sources carry one) so ast.parse
            # does not choke on U+FEFF.
            src = path.read_text(encoding="utf-8-sig", errors="replace")
            problems += check_source(path.relative_to(ROOT), src, in_collectors)
    if problems:
        print("Credential-on-command-line guard FAILED (roadmap 0.2 / H1):", file=sys.stderr)
        for problem in problems:
            print("  " + problem, file=sys.stderr)
        print(
            f"\n{len(problems)} problem(s). A credential must travel via env=, never on a command line.",
            file=sys.stderr,
        )
        return 1
    print("Credential-on-command-line guard passed: no credential reaches a subprocess command line.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
