"""M0/Q5: the source files stay readable by the tools that read source files.

Two defects the quality audit found are invisible on screen and neither breaks a
test, which is exactly why they need a static check instead:

* `collectors/file_scanner.py` and `collectors/winrm_endpoint_scanner.py` began with
  a UTF-8 byte-order mark. Python tolerates it; Scalene's source analysis crashed on
  both files and had to be told to skip them, and the next tool that parses source
  will hit the same thing.
* `tests/test_scan_and_dashboard_ui_contract.py` had a literal backspace where a
  regex word boundary was meant. The pattern could never match, so the assertion it
  guarded - no raw hex colours in the stylesheets - had been passing for free.

Both are cheap to prevent and impossible to spot in review, so they are asserted
over every tracked source file rather than the two that were wrong.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE_SUFFIXES = {".py", ".js", ".css", ".html", ".json", ".md", ".yml", ".yaml", ".txt"}
# Tab, newline and carriage return are the only control characters source may hold.
ALLOWED_CONTROL = {"\t", "\n", "\r"}


def _tracked_sources() -> list[Path]:
    # git ls-files in a checkout; the source files of a copy without git metadata otherwise.
    sys.path.insert(0, str(ROOT / "scripts"))
    import check_source_tree

    listing = check_source_tree.tracked_files(ROOT)
    return [ROOT / name for name in listing
            if Path(name).suffix.lower() in SOURCE_SUFFIXES and (ROOT / name).is_file()]


class EverySourceFileTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.sources = _tracked_sources()

    def test_there_are_sources_to_check(self) -> None:
        # A broken listing would make every other test here vacuously true.
        self.assertGreater(len(self.sources), 100, "git ls-files returned almost nothing")

    def test_none_starts_with_a_byte_order_mark(self) -> None:
        marked = [str(path.relative_to(ROOT)) for path in self.sources
                  if path.read_bytes()[:3] == b"\xef\xbb\xbf"]
        self.assertEqual(marked, [], "a UTF-8 BOM breaks source-analysing tools")

    def test_none_holds_a_stray_control_character(self) -> None:
        offenders: list[str] = []
        for path in self.sources:
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:  # not text after all; nothing to check
                continue
            for number, line in enumerate(text.splitlines(), 1):
                stray = {char for char in line if ord(char) < 32 and char not in ALLOWED_CONTROL}
                if stray:
                    offenders.append(f"{path.relative_to(ROOT)}:{number} {sorted(hex(ord(c)) for c in stray)}")
        self.assertEqual(offenders, [], "a control character in source is invisible in review")


if __name__ == "__main__":
    unittest.main()
