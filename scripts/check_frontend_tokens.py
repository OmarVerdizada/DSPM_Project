"""Frontend token discipline gate (roadmap F0).

The console's stylesheet reached 24,000 lines and 3,760 ``!important``
declarations because every fix was layered on the last one. Rewriting it in one
pass is not an option while the product ships, so this gate does the next best
thing: it **freezes the debt**. Existing lines are left alone; only lines a
change *adds* are checked, so the refit can proceed page by page (phase F3)
without the pile growing underneath it.

Four rules, each tied to a measured problem in the assessment:

1. **No new ``!important``** — 3,760 of them are why position and spacing cannot
   be reasoned about. Every new one makes the next fix harder.
2. **No raw colour outside the token file** — 246 hard-coded hex values against
   16 declared roles. A colour that is not a token cannot be themed, and dark
   mode silently drifts.
3. **No font-size outside the scale** — 43 distinct sizes in a product that
   needs six. Sizes below 12px (there are 3px and 7px labels today) are always
   rejected, new or not, because they are unreadable rather than merely
   inconsistent.
4. **No ``text-transform: uppercase`` outside an eyebrow** — 83 rules shout, so
   nothing stands out.

Usage:
    python scripts/check_frontend_tokens.py                 # working tree vs HEAD
    python scripts/check_frontend_tokens.py --base origin/main
    python scripts/check_frontend_tokens.py --stats         # report the debt, exit 0
    python scripts/check_frontend_tokens.py --base origin/main --write-baseline

Exit code 1 means a changed line breaks a rule. The message names the file, the
line and the token to use instead. Exit code 2 means the diff itself failed (an
unknown base, a shallow clone): that is never reported as "clean".

The baseline (frontend/token-gate-baseline.json) is debt that exists on this
branch but not yet on the base it is compared with: lines the F0-F4 refit added
while it stayed unmerged, and the sign-in page's styles C6 moved out of an inline
<style> block into login.css. Each entry is keyed by file, rule and the line's text
(not its number, so edits elsewhere do not disturb it) and counted, like the Bandit
baseline. A line beyond the baseline fails; D4 burns the baseline down.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TOKEN_FILE = "frontend/styles/tokens.css"
BASELINE = REPO / "frontend" / "token-gate-baseline.json"

# The type scale from tokens.css. Anything else must go through a var().
ALLOWED_PX = {12, 13, 14, 16, 20, 28}
MIN_PX = 12

CSS_PATHS = ("frontend/",)
CSS_SUFFIXES = (".css",)
# Generated third-party CSS would be reviewed through its source file and lockfile
# rather than line by line. There is none since D4 replaced the DaisyUI build with
# styles/components.css; every stylesheet the console loads is product-authored.
GENERATED_CSS_FILES: set[str] = set()

HEX = re.compile(r"#[0-9a-fA-F]{3,8}\b")
IMPORTANT = re.compile(r"!\s*important")
FONT_SIZE = re.compile(r"font-size\s*:\s*([^;}]+)")
UPPERCASE = re.compile(r"text-transform\s*:\s*uppercase")
PX = re.compile(r"(-?\d*\.?\d+)px")
COMMENT_ONLY = re.compile(r"^\s*(/\*|\*|//)")
ALLOW = re.compile(r"token-gate:\s*allow")


def changed_css_lines(base: str) -> list[tuple[str, int, str]]:
    """Added lines in CSS files, as (path, line number in new file, text)."""
    cmd = ["git", "diff", "--unified=0", "--no-color"]
    if base:
        cmd.append(base)
    run = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if run.returncode != 0:
        # An unknown base or a clone too shallow to hold it: nothing was compared, so
        # nothing may be reported clean.
        print(f"frontend token gate: git diff against {base or 'HEAD'!r} failed: {run.stderr.strip()[:300]}",
              file=sys.stderr)
        raise SystemExit(2)
    diff = run.stdout

    out: list[tuple[str, int, str]] = []
    path, lineno = None, 0
    for raw in diff.splitlines():
        if raw.startswith("+++ b/"):
            path = raw[6:]
            continue
        if raw.startswith("@@"):
            m = re.search(r"\+(\d+)", raw)
            lineno = int(m.group(1)) if m else 0
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            if path and path.startswith(CSS_PATHS) and path.endswith(CSS_SUFFIXES) and path not in GENERATED_CSS_FILES:
                out.append((path, lineno, raw[1:]))
            lineno += 1
        elif not raw.startswith("-"):
            lineno += 1
    return out


RULES = (("'!important'", "important"), ("raw colour", "raw-colour"), ("below the", "font-size-floor"),
         ("off the scale", "font-size-scale"), ("uppercase", "uppercase"))


def baseline_key(problem: str, text: str) -> tuple[str, str, str]:
    """(file, rule id, line text) for a problem check_line reported."""
    where, _, message = problem.partition(": ")
    rule = next((rule_id for marker, rule_id in RULES if marker in message), "other")
    return where.rsplit(":", 1)[0], rule, text.strip()


def check_line(path: str, lineno: int, text: str) -> list[str]:
    if COMMENT_ONLY.match(text) or not text.strip():
        return []
    # A deliberate exception carries its reason on the line:
    #   display: none !important; /* token-gate: allow — hides admin-only nav */
    # A gate with no way to say "yes, on purpose" gets switched off entirely,
    # so the escape hatch exists — but it has to be written down, which makes
    # it reviewable and greppable.
    if ALLOW.search(text):
        return []
    where = f"{path}:{lineno}"
    problems: list[str] = []

    if IMPORTANT.search(text):
        problems.append(
            f"{where}: new '!important'. Raise specificity by scoping the rule to its "
            f"component instead — the override pile is what F3 is removing."
        )

    if path != TOKEN_FILE and HEX.search(text) and "var(" not in text:
        found = ", ".join(sorted(set(HEX.findall(text))))
        problems.append(
            f"{where}: raw colour {found}. Use a role token from {TOKEN_FILE} "
            f"(--ink, --ink-muted, --paper, --surface, --line, --indigo) or a "
            f"--sev-* token if it means severity."
        )

    m = FONT_SIZE.search(text)
    if m:
        value = m.group(1).strip()
        if "var(" not in value:
            for px in (float(p) for p in PX.findall(value)):
                if px < MIN_PX:
                    problems.append(
                        f"{where}: font-size {px:g}px is below the {MIN_PX}px floor and is "
                        f"not readable. Use var(--text-xs)."
                    )
                elif px != int(px) or int(px) not in ALLOWED_PX:
                    scale = ", ".join(f"{s}px" for s in sorted(ALLOWED_PX))
                    problems.append(
                        f"{where}: font-size {px:g}px is off the scale ({scale}). "
                        f"Use var(--text-xs|sm|md|lg|xl|2xl)."
                    )

    if UPPERCASE.search(text) and "eyebrow" not in text.lower():
        problems.append(
            f"{where}: 'text-transform: uppercase' outside an eyebrow. Sentence case "
            f"reads faster; if this is a label, give it the .eyebrow class."
        )
    return problems


def debt_stats() -> dict:
    css = (REPO / "frontend" / "styles.css").read_text(encoding="utf-8", errors="ignore")
    sizes = {p for p in PX.findall(" ".join(FONT_SIZE.findall(css)))}
    return {
        "styles.css lines": css.count("\n") + 1,
        "!important": len(IMPORTANT.findall(css)),
        ":root:root hammers": css.count(":root:root"),
        "distinct font-size px": len(sizes),
        "distinct border-radius px": len({m for m in PX.findall(
            " ".join(re.findall(r"border-radius\s*:\s*([^;}]+)", css)))}),
        "box-shadow declarations": len(re.findall(r"box-shadow\s*:", css)),
        "uppercase rules": len(UPPERCASE.findall(css)),
        "raw hex colours": len(HEX.findall(css)),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="", help="git ref to diff against (default: working tree vs HEAD)")
    parser.add_argument("--stats", action="store_true", help="print the current debt counters and exit 0")
    parser.add_argument("--write-baseline", action="store_true",
                        help="record today's problems as reviewed debt in frontend/token-gate-baseline.json")
    args = parser.parse_args()

    if args.stats:
        for key, value in debt_stats().items():
            print(f"{key:<28} {value:>7}")
        return 0

    found: list[tuple[str, tuple[str, str, str]]] = []
    for path, lineno, text in changed_css_lines(args.base):
        found.extend((problem, baseline_key(problem, text)) for problem in check_line(path, lineno, text))

    if args.write_baseline:
        counts = Counter(key for _problem, key in found)
        entries = [{"file": file, "rule": rule, "text": text, "count": count}
                   for (file, rule, text), count in sorted(counts.items())]
        BASELINE.write_text(json.dumps({"reviewed": "2026-09-28", "base": args.base or "HEAD", "entries": entries},
                                       indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"frontend token gate: {len(found)} problem(s) recorded in {len(entries)} baseline entries")
        return 0

    allowed: Counter = Counter()
    if BASELINE.is_file():
        for entry in json.loads(BASELINE.read_text(encoding="utf-8"))["entries"]:
            allowed[(entry["file"], entry["rule"], entry["text"])] += int(entry["count"])
    problems: list[str] = []
    for problem, key in found:
        if allowed[key] > 0:
            allowed[key] -= 1
        else:
            problems.append(problem)

    if not problems:
        print(f"frontend token gate: clean ({len(found)} baseline debt line(s) carried)")
        return 0

    print(f"frontend token gate: {len(problems)} problem(s) in added CSS\n", file=sys.stderr)
    for problem in problems:
        print(f"  {problem}", file=sys.stderr)
    print(
        f"\nThe contract lives in {TOKEN_FILE}. Existing lines are exempt — this only "
        f"checks what your change adds, so the debt stops growing while F3 removes it.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
