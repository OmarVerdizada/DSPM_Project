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

Exit code 1 means a changed line breaks a rule. The message names the file, the
line and the token to use instead.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TOKEN_FILE = "frontend/styles/tokens.css"

# The type scale from tokens.css. Anything else must go through a var().
ALLOWED_PX = {12, 13, 14, 16, 20, 28}
MIN_PX = 12

CSS_PATHS = ("frontend/",)
CSS_SUFFIXES = (".css",)
# Generated third-party output is reviewed through its small source file and
# lockfile. Checking minified Tailwind/daisyUI internals as product-authored
# CSS would produce thousands of false positives.
GENERATED_CSS_FILES = {"frontend/styles/daisyui.css"}

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
    diff = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True).stdout

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
    args = parser.parse_args()

    if args.stats:
        for key, value in debt_stats().items():
            print(f"{key:<28} {value:>7}")
        return 0

    problems: list[str] = []
    for path, lineno, text in changed_css_lines(args.base):
        problems.extend(check_line(path, lineno, text))

    if not problems:
        print("frontend token gate: clean")
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
