"""C9: the Unicode font the PDF report embeds, read and written without a dependency.

The report used the base-14 Helvetica, which a PDF viewer supplies and which covers
Latin-1 only - so an Azerbaijani file name was transliterated ("müştəri" printed as
"musteri") and a Cyrillic one became question marks. A report is evidence about named
files; a name it cannot print is a name the reader cannot find.

This embeds Inter (backend/reporting/fonts/, built by scripts/build_report_fonts.py) as a
TrueType CID font: text is written as two-byte glyph ids (Identity-H), each font carries
its advance widths so a viewer lays the text out exactly as it was measured here, and a
ToUnicode map turns the glyphs back into the characters they came from, so the text can
be searched, copied and extracted.

Only the TrueType tables the writer needs are read: head (units per em, bounding box),
hhea and hmtx (advance widths), maxp (glyph count), cmap format 4 (character to glyph),
OS/2 (embedding permission, cap height) and post (italic angle).
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field, replace
from functools import lru_cache
from pathlib import Path

FONT_DIR = Path(__file__).resolve().parent / "fonts"
FONT_FILES = {False: "Inter-Report-Regular.ttf", True: "Inter-Report-Bold.ttf"}
FONT_NAMES = {False: "Inter-Regular", True: "Inter-Bold"}

# What a character with no glyph in the font is drawn as. Printed, not dropped: a
# silently shortened file name reads as a different file.
REPLACEMENT = "?"
# Characters the font lacks but that have an obvious drawable spelling.
FALLBACKS = {"\u2192": "->", "\u2190": "<-", "\u2194": "<->", "\u2026": "...", "\u00a0": " "}


class FontError(ValueError):
    pass


@dataclass
class TrueTypeFont:
    name: str
    data: bytes
    units_per_em: int
    bbox: tuple[int, int, int, int]
    ascent: int
    descent: int
    cap_height: int
    italic_angle: float
    advances: list[int]
    cmap: dict[int, int]
    used: dict[int, str] = field(default_factory=dict)

    # -- measuring and encoding --------------------------------------------------
    def _glyph(self, char: str) -> int | None:
        return self.cmap.get(ord(char))

    def printable(self, text: str) -> str:
        """`text` with every character the font cannot draw replaced by one it can."""
        out = []
        for char in text:
            if self._glyph(char) is not None:
                out.append(char)
            elif char in FALLBACKS:
                out.append(FALLBACKS[char])
            elif char in "\t\r\n":
                out.append(" ")
            else:
                out.append(REPLACEMENT)
        return "".join(out)

    def width(self, text: str, size: float) -> float:
        """Advance width of `text` at `size` points."""
        units = 0
        for char in self.printable(text):
            gid = self._glyph(char) or 0
            units += self.advances[gid] if gid < len(self.advances) else self.advances[-1]
        return units * size / self.units_per_em

    def encode(self, text: str) -> str:
        """`text` as the hex glyph-id string a content stream shows with Tj, recording
        every glyph used so the ToUnicode map and the width array cover it."""
        ids = []
        for char in self.printable(text):
            gid = self._glyph(char)
            if gid is None:  # pragma: no cover - printable() only returns mapped characters
                gid = 0
            self.used.setdefault(gid, char)
            ids.append(f"{gid:04X}")
        return "<" + "".join(ids) + ">"

    # -- the PDF objects ---------------------------------------------------------
    def _scaled(self, value: float) -> int:
        return round(value * 1000 / self.units_per_em)

    def pdf_objects(self, first: int) -> list[bytes]:
        """The five objects that make this font usable from a page, numbered from
        `first`: Type0 font, CIDFontType2, descriptor, embedded file, ToUnicode map.
        The Type0 font (`first`) is the one a page's resources name."""
        descendant, descriptor, font_file, to_unicode = first + 1, first + 2, first + 3, first + 4
        glyphs = sorted(self.used)
        widths = " ".join(f"{gid} [{self._scaled(self.advances[gid] if gid < len(self.advances) else self.advances[-1])}]"
                          for gid in glyphs)
        x_min, y_min, x_max, y_max = (self._scaled(v) for v in self.bbox)
        flags = 32  # nonsymbolic: the font's own glyphs for standard Latin text
        compressed = zlib.compress(self.data, 9)
        cmap = _to_unicode_cmap(self.used)
        return [
            (f"<< /Type /Font /Subtype /Type0 /BaseFont /{self.name} /Encoding /Identity-H "
             f"/DescendantFonts [{descendant} 0 R] /ToUnicode {to_unicode} 0 R >>").encode("ascii"),
            (f"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /{self.name} "
             f"/CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> "
             f"/FontDescriptor {descriptor} 0 R /CIDToGIDMap /Identity /DW 1000 /W [{widths}] >>").encode("ascii"),
            (f"<< /Type /FontDescriptor /FontName /{self.name} /Flags {flags} "
             f"/FontBBox [{x_min} {y_min} {x_max} {y_max}] /ItalicAngle {self.italic_angle:g} "
             f"/Ascent {self._scaled(self.ascent)} /Descent {self._scaled(self.descent)} "
             f"/CapHeight {self._scaled(self.cap_height)} /StemV 80 /FontFile2 {font_file} 0 R >>").encode("ascii"),
            (f"<< /Length {len(compressed)} /Length1 {len(self.data)} /Filter /FlateDecode >>\nstream\n").encode("ascii")
            + compressed + b"\nendstream",
            f"<< /Length {len(cmap)} >>\nstream\n".encode("ascii") + cmap + b"\nendstream",
        ]


def _to_unicode_cmap(used: dict[int, str]) -> bytes:
    entries = sorted(used.items())
    lines = [
        "/CIDInit /ProcSet findresource begin", "12 dict begin", "begincmap",
        "/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def",
        "/CMapName /Adobe-Identity-UCS def", "/CMapType 2 def",
        "1 begincodespacerange", "<0000> <FFFF>", "endcodespacerange",
    ]
    for start in range(0, len(entries), 100):  # a bfchar block holds at most 100 entries
        chunk = entries[start:start + 100]
        lines.append(f"{len(chunk)} beginbfchar")
        lines.extend(f"<{gid:04X}> <{char.encode('utf-16-be').hex().upper()}>" for gid, char in chunk)
        lines.append("endbfchar")
    lines += ["endcmap", "CMapName currentdict /CMap defineresource pop", "end", "end"]
    return "\n".join(lines).encode("ascii")


# -- reading TrueType -------------------------------------------------------------
def _tables(data: bytes) -> dict[str, bytes]:
    if len(data) < 12:
        raise FontError("not a font file")
    version, count = struct.unpack(">IH", data[:6])
    if version not in (0x00010000, 0x74727565):
        raise FontError("not a TrueType font")
    tables = {}
    for index in range(count):
        tag, _checksum, offset, length = struct.unpack(">4sIII", data[12 + index * 16: 28 + index * 16])
        if offset + length > len(data):
            raise FontError(f"table {tag!r} runs past the end of the file")
        tables[tag.decode("latin-1")] = data[offset:offset + length]
    for required in ("head", "hhea", "hmtx", "maxp", "cmap"):
        if required not in tables:
            raise FontError(f"the font has no {required} table")
    return tables


def _cmap_format4(cmap: bytes) -> dict[int, int]:
    _version, count = struct.unpack(">HH", cmap[:4])
    for index in range(count):
        platform, encoding, offset = struct.unpack(">HHI", cmap[4 + index * 8: 12 + index * 8])
        if (platform, encoding) not in ((3, 1), (0, 3), (0, 4)):
            continue
        if struct.unpack(">H", cmap[offset:offset + 2])[0] != 4:
            continue
        seg_count = struct.unpack(">H", cmap[offset + 6: offset + 8])[0] // 2
        ends_at = offset + 14
        starts_at = ends_at + seg_count * 2 + 2
        deltas_at = starts_at + seg_count * 2
        ranges_at = deltas_at + seg_count * 2
        mapping: dict[int, int] = {}
        for segment in range(seg_count):
            end = struct.unpack(">H", cmap[ends_at + segment * 2: ends_at + segment * 2 + 2])[0]
            start = struct.unpack(">H", cmap[starts_at + segment * 2: starts_at + segment * 2 + 2])[0]
            delta = struct.unpack(">h", cmap[deltas_at + segment * 2: deltas_at + segment * 2 + 2])[0]
            range_offset_at = ranges_at + segment * 2
            range_offset = struct.unpack(">H", cmap[range_offset_at: range_offset_at + 2])[0]
            if start == 0xFFFF:
                continue
            for code in range(start, end + 1):
                if range_offset == 0:
                    glyph = (code + delta) & 0xFFFF
                else:
                    at = range_offset_at + range_offset + (code - start) * 2
                    glyph = struct.unpack(">H", cmap[at:at + 2])[0]
                    if glyph:
                        glyph = (glyph + delta) & 0xFFFF
                if glyph:
                    mapping[code] = glyph
        return mapping
    raise FontError("the font has no Unicode BMP character map (cmap format 4)")


def read_truetype(data: bytes, name: str) -> TrueTypeFont:
    tables = _tables(data)
    head = tables["head"]
    units_per_em = struct.unpack(">H", head[18:20])[0]
    bbox = struct.unpack(">hhhh", head[36:44])
    hhea = tables["hhea"]
    ascent, descent = struct.unpack(">hh", hhea[4:8])
    metric_count = struct.unpack(">H", hhea[34:36])[0]
    glyph_count = struct.unpack(">H", tables["maxp"][4:6])[0]
    hmtx = tables["hmtx"]
    advances = [struct.unpack(">H", hmtx[i * 4: i * 4 + 2])[0] for i in range(metric_count)]
    advances += [advances[-1]] * max(0, glyph_count - metric_count)
    cap_height = ascent
    os2 = tables.get("OS/2")
    if os2 is not None:
        fs_type = struct.unpack(">H", os2[8:10])[0]
        # Bit 1: restricted licence embedding - the font may not be embedded at all.
        if fs_type & 0x0002:
            raise FontError("the font's licence forbids embedding it")
        if len(os2) >= 90:
            cap_height = struct.unpack(">h", os2[88:90])[0] or ascent
    italic_angle = 0.0
    post = tables.get("post")
    if post is not None and len(post) >= 8:
        whole, fraction = struct.unpack(">hH", post[4:8])
        italic_angle = whole + fraction / 65536
    return TrueTypeFont(
        name=name, data=data, units_per_em=units_per_em or 1000, bbox=tuple(bbox), ascent=ascent,
        descent=descent, cap_height=cap_height, italic_angle=italic_angle, advances=advances,
        cmap=_cmap_format4(tables["cmap"]),
    )


@lru_cache(maxsize=4)
def _parsed(path: str, name: str) -> TrueTypeFont:
    return read_truetype(Path(path).read_bytes(), name)


def load(bold: bool = False, directory: Path | None = None) -> TrueTypeFont | None:
    """The font for one document - parsed once per process, with a `used` set of its
    own - or None when the file is missing or unreadable; the renderer then falls back
    to Helvetica and says so."""
    path = (directory or FONT_DIR) / FONT_FILES[bold]
    try:
        return replace(_parsed(str(path), FONT_NAMES[bold]), used={})
    except (OSError, FontError, struct.error):
        return None
