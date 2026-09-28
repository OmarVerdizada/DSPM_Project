"""C9: build the font the PDF report embeds, from the Inter the console already ships.

    python scripts/build_report_fonts.py        # after `npm ci` in frontend/

The PDF renderer used the base-14 Helvetica, which is Latin-1 only: an Azerbaijani file
name lost its letters to transliteration and a Cyrillic one became question marks. It now
embeds Inter as a TrueType CID font. @fontsource/inter (pinned in frontend/package.json)
ships Inter as per-script subsets; this merges the scripts a customer's file names are
written in - Latin, Latin Extended (Azerbaijani, Turkish), Cyrillic, Cyrillic Extended
(Azerbaijani Cyrillic) and Greek - into one TrueType file per weight, so the renderer
needs no font switching inside a word.

The output is committed (backend/reporting/fonts/), so neither fontTools nor node_modules
is needed to render a report. Inter is under the SIL Open Font License 1.1 with no
Reserved Font Name; the licence travels beside the files.
"""

from __future__ import annotations

import io
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "frontend" / "node_modules" / "@fontsource" / "inter"
TARGET = ROOT / "backend" / "reporting" / "fonts"
SUBSETS = ("latin", "latin-ext", "cyrillic", "cyrillic-ext", "greek")
WEIGHTS = {"Regular": 400, "Bold": 700}


def _decompressed(path: Path) -> io.BytesIO:
    from fontTools.ttLib import TTFont

    font = TTFont(str(path))
    font.flavor = None
    out = io.BytesIO()
    font.save(out)
    out.seek(0)
    return out


def build() -> list[Path]:
    from fontTools.merge import Merger
    from fontTools.ttLib import TTFont

    if not SOURCE.is_dir():
        raise SystemExit(f"{SOURCE} is missing: run `npm ci` in frontend/ first")
    TARGET.mkdir(parents=True, exist_ok=True)
    written = []
    for style, weight in WEIGHTS.items():
        parts = [_decompressed(SOURCE / "files" / f"inter-{subset}-{weight}-normal.woff") for subset in SUBSETS]
        merged = Merger().merge(parts)
        # Hinting instructions are for screens at small pixel sizes; a PDF viewer scales
        # outlines. Dropping them roughly halves the file every report carries.
        # Nor does the renderer shape text, so the layout tables go too.
        for table in ("fpgm", "prep", "cvt ", "gasp", "hdmx", "LTSH", "VDMX", "GSUB", "GPOS", "GDEF"):
            if table in merged:
                del merged[table]
        for glyph in merged["glyf"].glyphs.values():
            if hasattr(glyph, "program"):
                glyph.program = None
        # Embedding is permitted by the licence; say so in the font itself.
        merged["OS/2"].fsType = 0
        destination = TARGET / f"Inter-Report-{style}.ttf"
        merged.save(str(destination))
        TTFont(str(destination))  # it reads back
        written.append(destination)
    shutil.copyfile(SOURCE / "LICENSE", TARGET / "OFL.txt")
    written.append(TARGET / "OFL.txt")
    return written


if __name__ == "__main__":
    for path in build():
        print(f"{path.relative_to(ROOT)}  {path.stat().st_size:,} bytes")
    sys.exit(0)
