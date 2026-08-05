"""M8 (roadmap 1.3): Office/ODT extraction is bounded and defused.

- a billion-laughs .docx is neutralized (defusedxml), not expanded;
- a compression-bomb / oversized part is skipped or byte-capped, not inflated;
- legit documents still extract their text (no regression)."""

from __future__ import annotations

import os
import time
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

import collectors.binary_extractor as be


BILLION_LAUGHS = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
 <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
 <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
 <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<w:document xmlns:w="x"><w:body><w:t>&lol9;</w:t></w:body></w:document>"""


def _write_zip(path: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)


class BillionLaughsTests(unittest.TestCase):
    def test_docx_entity_bomb_is_neutralized(self) -> None:
        with TemporaryDirectory() as d:
            path = Path(d) / "bomb.docx"
            _write_zip(path, {"word/document.xml": BILLION_LAUGHS})
            started = time.monotonic()
            out = be.extract_binary_text(path)
            elapsed = time.monotonic() - started
        self.assertEqual(out, "")        # entity expansion blocked -> no text
        self.assertLess(elapsed, 2.0)    # did not hang expanding the bomb

    def test_parse_xml_blocks_entities_but_parses_legit(self) -> None:
        self.assertIsNone(be._parse_xml(BILLION_LAUGHS))          # forbidden
        self.assertIsNotNone(be._parse_xml(b"<a><b>hi</b></a>"))  # legit still parses


class InflationTests(unittest.TestCase):
    def test_compression_ratio_bomb_is_skipped(self) -> None:
        with TemporaryDirectory() as d:
            path = Path(d) / "bomb.xlsx"
            _write_zip(path, {"xl/worksheets/sheet1.xml": b" " * (4 * 1024 * 1024)})
            with zipfile.ZipFile(path) as archive:
                data = be._read_zip_member(archive, "xl/worksheets/sheet1.xml")
            self.assertEqual(data, b"")  # inflate ratio >> 200 -> rejected unread

    def test_bounded_read_caps_bytes(self) -> None:
        with TemporaryDirectory() as d:
            path = Path(d) / "x.zip"
            _write_zip(path, {"part.xml": os.urandom(200_000)})  # ~incompressible
            with zipfile.ZipFile(path) as archive:
                data = be._read_zip_member(archive, "part.xml", max_bytes=1024)
            self.assertLessEqual(len(data), 1024)

    def test_missing_member_returns_empty(self) -> None:
        with TemporaryDirectory() as d:
            path = Path(d) / "x.zip"
            _write_zip(path, {"a.xml": b"<a/>"})
            with zipfile.ZipFile(path) as archive:
                self.assertEqual(be._read_zip_member(archive, "nope.xml"), b"")

    def test_extract_of_bomb_xlsx_is_bounded_and_fast(self) -> None:
        with TemporaryDirectory() as d:
            path = Path(d) / "bomb.xlsx"
            _write_zip(path, {"xl/worksheets/sheet1.xml": b"<x>" + b" " * (8 * 1024 * 1024) + b"</x>"})
            started = time.monotonic()
            out = be.extract_binary_text(path)  # must not OOM/hang
            elapsed = time.monotonic() - started
        self.assertIsInstance(out, str)
        self.assertLess(elapsed, 3.0)


class RegressionTests(unittest.TestCase):
    def test_legit_docx_still_extracts(self) -> None:
        with TemporaryDirectory() as d:
            path = Path(d) / "ok.docx"
            xml = (
                b'<?xml version="1.0"?><w:document xmlns:w="x"><w:body><w:p>'
                b"<w:t>Card 4111 1111 1111 1111</w:t></w:p></w:body></w:document>"
            )
            _write_zip(path, {"word/document.xml": xml})
            out = be.extract_binary_text(path)
        self.assertIn("4111 1111 1111 1111", out)

    def test_legit_xlsx_inline_string_still_extracts(self) -> None:
        with TemporaryDirectory() as d:
            path = Path(d) / "ok.xlsx"
            sheet = (
                b'<worksheet xmlns="x"><sheetData><row r="1">'
                b'<c r="A1" t="inlineStr"><is><t>Secret 12345</t></is></c>'
                b"</row></sheetData></worksheet>"
            )
            _write_zip(path, {"xl/worksheets/sheet1.xml": sheet})
            out = be.extract_binary_text(path)
        self.assertIn("Secret 12345", out)


if __name__ == "__main__":
    unittest.main()
