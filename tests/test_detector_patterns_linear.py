"""The detectors' patterns take time in proportion to the text, whatever the text is.

Found 2026-09-29 while testing D5: the masked-PAN pattern took four minutes on 64 KB of
"x" - two adjacent `x{2,}` groups split one run every possible way, so its time grew with
the square of the run - and never finished on a run of "*". A file of masked values (an
export with its digits x-ed out) would have held a scan worker for hours. A sweep of every
pattern the detection code compiles found four more that grew with the square of a run:
the secret-assignment, push-token and e-mail patterns on identifier-like runs ("a.a.a...",
"x-x-x...") - each started again at every word boundary inside the run - and the money
amount on whitespace. Each is rewritten to be linear, and each rewrite is checked against
the pattern it replaced.

The sweep itself is the last test: every compiled pattern in the detection, collection,
risk and permission code, on long runs of the characters such data is made of. It judges a
pattern by how its time grows when the run doubles - a linear one doubles, one that grows
with the square quadruples - so a loaded machine neither hides nor invents one. It runs in
a child process with a deadline, so a pattern that never finishes fails the test rather
than hanging the suite.
"""

from __future__ import annotations

import importlib
import pkgutil
import random
import re
import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGES = ("classification", "collectors", "discovery", "risk", "permissions")
RUNS = ["x", "X", "*", "0", "a", " ", "-", "=", "A", "1 ", "a ", "x-", ".", "/", "@", "_", "\t", "ab", "1", "9-",
        "a.", "x ", "*-", "password"]
RUN_LENGTH = 12_000
# Growing with the square of the run shows as ~4x for twice the run; linear, ~2x. Only a
# pattern measurably slow at RUN_LENGTH is judged by its growth, and one past the hard
# ceiling is slow whatever its growth.
GROWTH_LIMIT = 3.0
MEASURABLE_SECONDS = 0.05
HARD_CEILING_SECONDS = 2.0

# The patterns as they were, to show the rewrites find what they found.
OLD_MASKED_PAN = re.compile(r"(?<!\w)(?:\d{0,6}[\s-]?)?(?:\*{2,}|x{2,}|X{2,})[\s*-]*(?:\*{2,}|x{2,}|X{2,})?[\s-]*\d{4}(?!\w)")
OLD_MONEY = re.compile(r"(?<!\w)(?:[$€£₼]|AZN|USD|EUR|GBP)?\s*\d{1,3}(?:[ ,]\d{3})*(?:\.\d{2})?\s*(?:AZN|USD|EUR|GBP|manat)?(?!\w)",
                       re.IGNORECASE)
OLD_SECRET = re.compile(
    r"\b[A-Za-z0-9_.-]*(?:password|passwd|pwd|passphrase|secret|token|api[_-]?key|client[_-]?secret|private[_-]?key)"
    r"[A-Za-z0-9_.-]*\s*[:=]\s*([^\s'\";,#]{6,512}|['\"][^'\"]{6,512}['\"])",
    re.IGNORECASE)
OLD_PUSH_TOKEN = re.compile(r"\b[A-Za-z0-9_-]{80,}:[A-Za-z0-9_-]{20,}\b")
OLD_EMAIL = re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b")


def _texts(alphabet: str, count: int, seed: int, prefixes: tuple[str, ...] = ()) -> list[str]:
    rng = random.Random(seed)
    texts = []
    for _ in range(count):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 40)))
        if prefixes and rng.random() < 0.5:
            text = rng.choice(prefixes) + text
        texts.append(text)
    return texts


class TheRewritesFindWhatTheOldPatternsFoundTest(unittest.TestCase):

    def test_masked_pan_matches_exactly_as_before(self) -> None:
        from classification.compliance.pci_validators import MASKED_PAN_RE

        for text in _texts("xX*-  0123456789aZ\n.", 20_000, 29):
            with self.subTest(text=text):
                self.assertEqual([m.span() for m in MASKED_PAN_RE.finditer(text)],
                                 [m.span() for m in OLD_MASKED_PAN.finditer(text)])
        for masked in ("xxxx-xxxx-xxxx-1234", "**** **** **** 4242", "411111xxxxxx1111", "XXXXXXXXXXXX0005"):
            self.assertTrue(MASKED_PAN_RE.search(f"card: {masked}"), masked)

    def test_a_money_amount_is_the_same_amount(self) -> None:
        from classification.compliance.validators import MONEY_AMOUNT_RE

        for text in _texts(" \t\n0123456789,.$€AZNUSDmanat:-x", 20_000, 30):
            with self.subTest(text=text):
                # Values are fingerprinted stripped; the amount no longer starts with the
                # whitespace before it, and is otherwise the same, ending where it ended.
                self.assertEqual([(m.group(0).strip(), m.end()) for m in MONEY_AMOUNT_RE.finditer(text)],
                                 [(m.group(0).strip(), m.end()) for m in OLD_MONEY.finditer(text)])
        self.assertEqual(MONEY_AMOUNT_RE.search("Salary:   12,000 AZN").group(0), "12,000 AZN")
        self.assertEqual(MONEY_AMOUNT_RE.search("paid $ 1,250.00 in May").group(0), "$ 1,250.00")

    def test_a_secret_assignment_yields_the_same_value(self) -> None:
        from classification.compliance.validators import SECRET_ASSIGNMENT_RE

        texts = _texts("passwordtokenkeyapi_-.:= '\"a1Zé\n#;secrtpwd", 20_000, 31,
                       ("password", "api_key", "token", "secret", "db.password", "-pwd", ".token", "é-secret"))
        for text in texts:
            with self.subTest(text=text):
                self.assertEqual([(m.end(), m.groups()) for m in SECRET_ASSIGNMENT_RE.finditer(text)],
                                 [(m.end(), m.groups()) for m in OLD_SECRET.finditer(text)])
        self.assertEqual(SECRET_ASSIGNMENT_RE.search("db.password = Hunter2-Blue").group(1), "Hunter2-Blue")

    def test_a_push_token_is_the_same_token(self) -> None:
        from classification.compliance.validators import PUSH_TOKEN_RE

        rng = random.Random(32)
        for _ in range(3_000):
            text = "".join(rng.choice("ab_-:é ") for _ in range(rng.randint(1, 300)))
            with self.subTest(text=text):
                # A token may now start at its run's leading "-"; otherwise the same.
                self.assertEqual([(m.group(0).lstrip("-"), m.end()) for m in PUSH_TOKEN_RE.finditer(text)],
                                 [(m.group(0).lstrip("-"), m.end()) for m in OLD_PUSH_TOKEN.finditer(text)])

    def test_an_email_address_is_the_same_address(self) -> None:
        from classification.regex_classifier import RULES

        email = next(rule.pattern for rule in RULES if rule.name == "email")
        rng = random.Random(33)
        locals_ = "ana leyla john.doe j_smith first+tag o-brien x1 support info a.b.c".split()
        domains = "example.com corp.az mail.example.org x-y.co.uk sub.domain.net".split()
        separators = [" ", ", ", "; ", "\n", " <", "> ", "\t", " (", ") ", ": "]
        for _ in range(20_000):
            parts = []
            for _ in range(rng.randint(1, 6)):
                parts.append(rng.choice(separators))
                parts.append(f"{rng.choice(locals_)}@{rng.choice(domains)}" if rng.random() < 0.6
                             else rng.choice([*locals_, "Email:", "to", "cc"]))
            text = "".join(parts)
            with self.subTest(text=text):
                self.assertEqual([m.span() for m in email.finditer(text)], [m.span() for m in OLD_EMAIL.finditer(text)])
        self.assertIsNone(email.search(" -@y.com"), "a local part that is only punctuation is not an address")
        self.assertEqual(email.search("Contact: o-brien+cc@mail.example.org.").group(0), "o-brien+cc@mail.example.org")


def pci_runs() -> list[str]:
    """The PCI classifier on 256 KB of each run that took minutes, with a masked PAN after it.

    256 KB, not the 64 KB that first showed it: the fixed classifier reads it in under half
    a second, and a start re-tried at every * of a run only shows at this size."""
    from classification.compliance.pci_classifier import classify_pci_content

    lines = []
    for filler in ("x", "X", "*"):
        text = filler * 256_000 + "\nCard number on file: xxxx-xxxx-xxxx-4242\n"
        began = time.perf_counter()
        findings = classify_pci_content(text, {"name": "export.txt", "path": "export.txt"})
        found = "pci_chd_masked_pan" in {finding["type"] for finding in findings}
        lines.append(f"PCI {filler!r} {time.perf_counter() - began:.2f} {'found' if found else 'missed'}")
    return lines


def _nested(value, path: str, depth: int):
    """Patterns in a module attribute: itself, or inside its lists, dicts and objects."""
    if isinstance(value, re.Pattern):
        yield path, value
        return
    if depth > 3 or isinstance(value, (str, bytes, int, float, type)):
        return
    if isinstance(value, dict):
        for key, item in list(value.items())[:5000]:
            yield from _nested(item, f"{path}[{key!r}]", depth + 1)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for index, item in enumerate(list(value)[:5000]):
            yield from _nested(item, f"{path}[{index}]", depth + 1)
    elif type(value).__module__.split(".")[0] in PACKAGES:
        attributes = vars(value) if hasattr(value, "__dict__") else {key: getattr(value, key, None)
                                                                   for key in getattr(value, "__slots__", ())}
        for key, item in attributes.items():
            yield from _nested(item, f"{path}.{key}", depth + 1)


def compiled_patterns() -> dict[str, re.Pattern]:
    found: dict[str, re.Pattern] = {}
    for package_name in PACKAGES:
        package = importlib.import_module(package_name)
        for info in pkgutil.walk_packages(package.__path__, package_name + "."):
            try:
                module = importlib.import_module(info.name)
            except Exception:  # noqa: BLE001, S112 - an optional module that does not import compiles nothing here
                continue
            for name, value in vars(module).items():
                for path, pattern in _nested(value, name, 0):
                    found.setdefault(f"{info.name}.{path}", pattern)
    unique: dict[str, re.Pattern] = {}
    seen: set = set()
    for key, pattern in sorted(found.items()):
        if (pattern.pattern, pattern.flags) not in seen:
            seen.add((pattern.pattern, pattern.flags))
            unique[key] = pattern
    return unique


def sweep() -> list[str]:
    """Every pattern on every run: the ones whose time grows faster than the run."""

    def timed(pattern, text) -> float:
        best = float("inf")
        for _ in range(2):  # the better of two, so a scheduling hiccup is not a verdict
            began = time.perf_counter()
            list(pattern.finditer(text))
            best = min(best, time.perf_counter() - began)
        return best

    slow = []
    for key, pattern in compiled_patterns().items():
        for run in RUNS:
            full = timed(pattern, run * (RUN_LENGTH // len(run)))
            if full < MEASURABLE_SECONDS:
                continue
            half = timed(pattern, run * (RUN_LENGTH // 2 // len(run)))
            growth = full / max(half, 1e-6)
            if growth > GROWTH_LIMIT or full > HARD_CEILING_SECONDS:
                slow.append(f"{key} on {run!r} x {RUN_LENGTH}: {full:.2f}s, x{growth:.1f} for twice the run")
    return slow


class EveryPatternIsLinearTest(unittest.TestCase):
    """In a child process with a deadline: a pattern that never finishes fails the test."""

    @classmethod
    def setUpClass(cls) -> None:
        try:
            run = subprocess.run([sys.executable, __file__, "--sweep"], cwd=ROOT, capture_output=True, text=True,
                                 timeout=300, check=False)
        except subprocess.TimeoutExpired:
            cls.lines, cls.error = [], "a pattern did not finish on a long run of one character within five minutes"
            return
        cls.lines = run.stdout.strip().splitlines()
        cls.error = "" if run.returncode == 0 else run.stderr[-2000:]

    def setUp(self) -> None:
        self.assertFalse(self.error, self.error)

    def test_the_pci_classifier_reads_long_masked_runs_in_time(self) -> None:
        results = [line.split() for line in self.lines if line.startswith("PCI ")]
        self.assertEqual(len(results), 3)
        for _, filler, seconds, found in results:
            with self.subTest(filler=filler):
                self.assertLess(float(seconds), 5.0, "it took minutes before, and never finished on *")
                self.assertEqual(found, "found", "the masked PAN after the run is still found")

    def test_no_compiled_pattern_slows_down_on_a_long_run(self) -> None:
        self.assertTrue(self.lines and self.lines[-1].startswith("patterns:"), self.lines[-5:])
        self.assertGreater(int(self.lines[-1].split(":")[1]), 100, "the sweep must find the detectors' patterns")
        self.assertEqual([line for line in self.lines if line.startswith("SLOW ")], [])


if __name__ == "__main__":
    if sys.argv[1:] == ["--sweep"]:
        sys.path.insert(0, str(ROOT))
        for line in pci_runs():
            print(line, flush=True)
        for line in sweep():
            print(f"SLOW {line}", flush=True)
        print(f"patterns:{len(compiled_patterns())}", flush=True)
    else:
        unittest.main()
