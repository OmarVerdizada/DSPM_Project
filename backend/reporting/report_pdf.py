"""Shared dependency-free visual renderer for every SENTRO DSPM PDF report.

C9: text is drawn in Inter, embedded as a Unicode CID font (pdf_font.py), so a file name
in Azerbaijani, Russian or Greek prints as itself. Every string passes the shared export
masking (classification.masking.mask_in_text) on its way onto a page, the same pass the
Word and Excel exports use. Without the font files the renderer falls back to Helvetica
and the old Latin-1 transliteration, and the artifact metadata says which it used.
"""
from __future__ import annotations

import re
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from backend.reporting import pdf_font
from classification.masking import mask_in_text


PAGE_WIDTH = 842.0
PAGE_HEIGHT = 595.0
MARGIN = 32.0
CONTENT_WIDTH = PAGE_WIDTH - (MARGIN * 2)
# The cover headline's band: the scan id and generation stamp start 290pt from the
# right edge, and the title must stop before them.
HEADLINE_WIDTH = PAGE_WIDTH - 290 - MARGIN - 14

REPORT_TEMPLATE_ID = "sentro-dspm-unified-v1"

# The model composes the document title (it knows the scope); this stands in only
# when a caller builds a model without one. This module stays dependency-free, so it
# does not import the model to borrow the constant.
FALLBACK_TITLE = "DSPM Assessment Report"

INK = (0.059, 0.090, 0.165)
MUTED = (0.392, 0.455, 0.545)
LINE = (0.824, 0.855, 0.902)
SOFT = (0.969, 0.980, 0.992)
SENTRO_NAVY = (0.043, 0.090, 0.224)
SENTRO_DEEP_BLUE = (0.063, 0.165, 0.337)
SENTRO_BLUE = (0.145, 0.388, 0.922)
SENTRO_INDIGO = (0.310, 0.275, 0.898)
SENTRO_PURPLE = (0.486, 0.227, 0.929)
SENTRO_PALE_BLUE = (0.933, 0.957, 1.000)
WHITE = (1.0, 1.0, 1.0)

RISK_COLORS = {
    "CRITICAL": (0.624, 0.071, 0.224),
    "HIGH": (0.761, 0.255, 0.047),
    "MEDIUM": (0.718, 0.475, 0.122),
    "LOW": (0.082, 0.502, 0.239),
}
RISK_SOFT = {
    "CRITICAL": (1.0, 0.945, 0.953),
    "HIGH": (1.0, 0.969, 0.929),
    "MEDIUM": (0.996, 0.988, 0.878),
    "LOW": (0.941, 0.992, 0.957),
}

# Only for the fallback: without the embedded font the page is drawn in Helvetica,
# which is Latin-1, and these letters are mapped to their nearest ASCII form.
_TRANSLITERATION = str.maketrans(
    {
        "\u0259": "e", "\u018f": "E", "\u0131": "i", "\u0130": "I",
        "\u011f": "g", "\u011e": "G", "\u015f": "s", "\u015e": "S",
        "\u00e7": "c", "\u00c7": "C", "\u00f6": "o", "\u00d6": "O",
        "\u00fc": "u", "\u00dc": "U", "\u2013": "-", "\u2014": "-",
        "\u2022": "-", "\u00b7": "-", "\u2019": "'", "\u201c": '"', "\u201d": '"',
    }
)


class _Fonts:
    """The two embedded faces of one document, and the glyphs it used from each."""

    def __init__(self, regular: pdf_font.TrueTypeFont, bold: pdf_font.TrueTypeFont) -> None:
        self.faces = {False: regular, True: bold}

    def resource(self, bold: bool) -> str:
        return "/U1" if bold else "/U0"


# The document being rendered. A context variable rather than an argument, so the page
# builders keep their shape and two reports rendered at once never share a glyph set.
_DOCUMENT_FONTS: ContextVar[_Fonts | None] = ContextVar("report_pdf_fonts", default=None)


def _clean(value: Any, limit: int = 500) -> str:
    # None is nothing to print; 0 is a count. `value or ""` printed every zero as a blank.
    text = re.sub(r"\s+", " ", "" if value is None else str(value)).strip()
    # Masked before it is cut, so a card number at the limit is not half-kept.
    text, _masked = mask_in_text(text)
    if _DOCUMENT_FONTS.get() is not None:
        return text[:limit]
    text = text.translate(_TRANSLITERATION)
    return text.encode("latin-1", "replace").decode("latin-1")[:limit]


def _pdf_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _rgb(color: tuple[float, float, float]) -> str:
    return " ".join(f"{component:.3f}" for component in color)


def text_width(value: Any, size: float, bold: bool = False) -> float:
    """How wide `value` is drawn at `size` points: measured with the embedded font's own
    advance widths, or estimated at 0.52 em a character in the Helvetica fallback."""
    text = _clean(value)
    fonts = _DOCUMENT_FONTS.get()
    if fonts is None:
        return len(text) * size * 0.52
    return fonts.faces[bold].width(text, size)


def _wrap(value: Any, width: float, size: float, max_lines: int | None = None, *, bold: bool = False) -> list[str]:
    text = _clean(value)
    if not text:
        return [""]
    fonts = _DOCUMENT_FONTS.get()
    if fonts is None:
        max_chars = max(8, int(width / max(size * 0.52, 1)))

        def fits(candidate: str) -> bool:
            return len(candidate) <= max_chars
    else:
        face = fonts.faces[bold]

        def fits(candidate: str) -> bool:
            # `text` is already clean; measuring the pieces must not mask them again.
            return face.width(candidate, size) <= width

    def longest_prefix(word: str) -> int:
        # At least one character per line, so a word wider than the column still ends.
        cut = 1
        while cut < len(word) and fits(word[:cut + 1]):
            cut += 1
        return cut

    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        while not fits(word) and len(word) > 1:
            if current:
                lines.append(current)
                current = ""
            cut = longest_prefix(word)
            lines.append(word[:cut])
            word = word[cut:]
        candidate = f"{current} {word}".strip()
        if current and not fits(candidate):
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    if max_lines and len(lines) > max_lines:
        lines = lines[:max_lines]
        last = lines[-1]
        while last and not fits(last + "..."):
            last = last[:-1]
        lines[-1] = (last + "...") if last else "..."
    return lines or [""]


class _Page:
    def __init__(self) -> None:
        self.commands: list[str] = []

    def fill(self, color: tuple[float, float, float]) -> None:
        self.commands.append(f"{_rgb(color)} rg")

    def stroke(self, color: tuple[float, float, float], width: float = 1.0) -> None:
        self.commands.append(f"{_rgb(color)} RG")
        self.commands.append(f"{width:.2f} w")

    def rect(self, x: float, top: float, width: float, height: float, fill: tuple[float, float, float], stroke: tuple[float, float, float] | None = None) -> None:
        y = PAGE_HEIGHT - top - height
        self.fill(fill)
        if stroke:
            self.stroke(stroke)
            self.commands.append(f"{x:.2f} {y:.2f} {width:.2f} {height:.2f} re B")
        else:
            self.commands.append(f"{x:.2f} {y:.2f} {width:.2f} {height:.2f} re f")

    def line(self, x1: float, top1: float, x2: float, top2: float, color: tuple[float, float, float] = LINE, width: float = 1.0) -> None:
        self.stroke(color, width)
        y1 = PAGE_HEIGHT - top1
        y2 = PAGE_HEIGHT - top2
        self.commands.append(f"{x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S")

    def text(self, x: float, top: float, value: Any, size: float = 10.0, *, bold: bool = False, color: tuple[float, float, float] = INK) -> None:
        clean = _clean(value)
        if not clean:
            return
        baseline = PAGE_HEIGHT - top - size
        fonts = _DOCUMENT_FONTS.get()
        if fonts is not None:
            font, shown = fonts.resource(bold), fonts.faces[bold].encode(clean)
        else:
            font, shown = ("/F2" if bold else "/F1"), f"({_pdf_escape(clean)})"
        self.commands.extend(
            [
                "BT",
                f"{font} {size:.2f} Tf",
                f"{_rgb(color)} rg",
                f"{x:.2f} {baseline:.2f} Td",
                f"{shown} Tj",
                "ET",
            ]
        )

    def wrapped_text(self, x: float, top: float, value: Any, width: float, size: float = 9.0, *, bold: bool = False, color: tuple[float, float, float] = INK, leading: float | None = None, max_lines: int | None = None) -> float:
        line_height = leading or size * 1.32
        lines = _wrap(value, width, size, max_lines, bold=bold)
        for index, line in enumerate(lines):
            self.text(x, top + (index * line_height), line, size, bold=bold, color=color)
        return len(lines) * line_height


def _scope_label(model: dict) -> str:
    scope = model.get("scope") or {}
    return _clean(scope.get("label") or "Full scan", 120)


def _document_title(model: dict) -> str:
    return _clean(model.get("title") or FALLBACK_TITLE, 120)


def _fitted_headline(text: str, available: float, largest: float, smallest: float) -> tuple[str, float]:
    """One line of ``text`` that fits ``available``, with the size it fits at.

    The cover headline sits in a fixed band beside the scan id, so a scoped title
    shrinks rather than wrapping into the line below it; a title too long even at
    the smallest size is then truncated, because running into the neighbouring
    block is worse than an ellipsis. Width is measured as _wrap measures it.
    """
    size = largest
    while size > smallest and text_width(text, size, bold=True) > available:
        size -= 0.5
    return _wrap(text, available, size, max_lines=1, bold=True)[0], size


def _page_header(page: _Page, model: dict, section: str, page_number: int) -> None:
    page.rect(0, 0, PAGE_WIDTH, 50, SENTRO_NAVY)
    page.text(MARGIN, 16, "SENTRO", 13, bold=True, color=WHITE)
    page.text(MARGIN + 74, 17, section, 11, bold=True, color=(0.820, 0.875, 1.000))
    page.text(PAGE_WIDTH - 220, 17, f"Scan {_clean(model.get('scan_id'), 80)}", 8.5, color=(0.820, 0.875, 1.000))
    page.text(PAGE_WIDTH - 64, 17, f"{page_number:02d}", 9, bold=True, color=WHITE)


def _page_footer(page: _Page, model: dict, page_number: int) -> None:
    page.line(MARGIN, 568, PAGE_WIDTH - MARGIN, 568)
    page.text(MARGIN, 574, f"Scope: {_scope_label(model)}", 7.5, color=MUTED)
    page.text(PAGE_WIDTH - 150, 574, f"Page {page_number}", 7.5, color=MUTED)


def _metric_card(page: _Page, x: float, top: float, width: float, label: str, value: Any, *, fill: tuple[float, float, float] = SOFT, accent: tuple[float, float, float] = SENTRO_BLUE) -> None:
    page.rect(x, top, width, 58, fill, LINE)
    page.rect(x, top, 5, 58, accent)
    page.text(x + 13, top + 11, label.upper(), 7.5, bold=True, color=MUTED)
    page.text(x + 13, top + 27, value, 20, bold=True, color=INK)


def _bar(page: _Page, x: float, top: float, width: float, label: str, count: int, maximum: int, color: tuple[float, float, float]) -> None:
    page.text(x, top, label, 8.5, bold=True)
    page.text(x + width - 24, top, count, 8.5, bold=True)
    page.rect(x, top + 14, width, 8, (0.898, 0.914, 0.937))
    ratio = min(1.0, max(0.0, count / max(maximum, 1)))
    if count:
        page.rect(x, top + 14, max(7, width * ratio), 8, color)


def _summary_page(model: dict, page_number: int) -> _Page:
    page = _Page()
    page.rect(0, 0, PAGE_WIDTH, 92, SENTRO_NAVY)
    headline, headline_size = _fitted_headline(_document_title(model), HEADLINE_WIDTH, 25, 14)
    page.text(MARGIN, 20, headline, headline_size, bold=True, color=WHITE)
    page.text(MARGIN, 55, f"Scope: {_scope_label(model)}", 10, bold=True, color=(0.820, 0.875, 1.000))
    page.text(PAGE_WIDTH - 290, 24, f"Scan {_clean(model.get('scan_id'), 90)}", 9, color=(0.820, 0.875, 1.000))
    page.text(PAGE_WIDTH - 290, 44, f"Generated {_clean(model.get('timestamp'), 90)}", 8, color=(0.820, 0.875, 1.000))

    posture = model.get("posture") or {}
    full = model.get("full_summary") or {}
    scoped = model.get("scoped_summary") or {}
    page.text(MARGIN, 112, "Executive summary", 16, bold=True)
    page.rect(MARGIN, 138, 478, 82, SOFT, LINE)
    page.text(MARGIN + 18, 153, posture.get("status_text") or "Risk posture assessed.", 12, bold=True, color=SENTRO_DEEP_BLUE)
    page.wrapped_text(MARGIN + 18, 178, f"This report contains {scoped.get('total_files', 0)} scoped evidence row(s). Priority exposure across the scan is {full.get('critical_high', 0)} critical or high files.", 440, 9.5, color=MUTED, max_lines=2)
    page.rect(MARGIN + 496, 138, 282, 82, SENTRO_PALE_BLUE, (0.745, 0.816, 1.000))
    page.text(MARGIN + 514, 151, "RISK POSTURE", 8, bold=True, color=SENTRO_INDIGO)
    page.text(MARGIN + 514, 169, f"{posture.get('score', 0)}/100", 28, bold=True, color=SENTRO_DEEP_BLUE)
    page.text(MARGIN + 660, 178, f"Grade {posture.get('grade', '')}", 11, bold=True, color=SENTRO_INDIGO)

    page.text(MARGIN, 244, "Risk posture", 14, bold=True)
    gap = 8
    card_width = (CONTENT_WIDTH - (gap * 5)) / 6
    cards = [
        ("Critical", full.get("critical", 0), RISK_SOFT["CRITICAL"], RISK_COLORS["CRITICAL"]),
        ("High", full.get("high", 0), RISK_SOFT["HIGH"], RISK_COLORS["HIGH"]),
        ("Medium", full.get("medium", 0), RISK_SOFT["MEDIUM"], RISK_COLORS["MEDIUM"]),
        ("Low", full.get("low", 0), RISK_SOFT["LOW"], RISK_COLORS["LOW"]),
        ("In scope", scoped.get("total_files", 0), SENTRO_PALE_BLUE, SENTRO_BLUE),
        ("All files", full.get("total_files", 0), SOFT, SENTRO_INDIGO),
    ]
    for index, (label, value, fill, accent) in enumerate(cards):
        _metric_card(page, MARGIN + (index * (card_width + gap)), 268, card_width, label, value, fill=fill, accent=accent)

    panel_width = (CONTENT_WIDTH - 12) / 2
    page.rect(MARGIN, 346, panel_width, 178, WHITE, LINE)
    page.text(MARGIN + 14, 360, "Risk distribution", 12, bold=True)
    distribution = model.get("distribution") or []
    maximum = max([int(item.get("count") or 0) for item in distribution] or [1])
    for index, item in enumerate(distribution[:4]):
        level = str(item.get("level") or "LOW").upper()
        _bar(page, MARGIN + 14, 386 + (index * 31), panel_width - 28, level.title(), int(item.get("count") or 0), maximum, RISK_COLORS.get(level, SENTRO_BLUE))

    right = MARGIN + panel_width + 12
    page.rect(right, 346, panel_width, 178, WHITE, LINE)
    page.text(right + 14, 360, "Detection signals", 12, bold=True)
    signals = model.get("detection_signals") or []
    signal_max = max([int(item.get("count") or 0) for item in signals[:5]] or [1])
    if signals:
        for index, item in enumerate(signals[:5]):
            _bar(page, right + 14, 386 + (index * 27), panel_width - 28, _clean(item.get("type"), 34), int(item.get("count") or 0), signal_max, SENTRO_INDIGO)
    else:
        page.text(right + 14, 392, "No detection signals in this scope.", 9, color=MUTED)

    _page_footer(page, model, page_number)
    return page


def _operations_page(model: dict, page_number: int) -> _Page:
    page = _Page()
    _page_header(page, model, "Response plan", page_number)
    page.text(MARGIN, 72, "Remediation plan", 15, bold=True)
    steps = model.get("remediation_steps") or []
    if not steps:
        steps = ["No scoped findings require remediation in this report."]
    top = 100.0
    for index, step in enumerate(steps[:6], start=1):
        page.rect(MARGIN, top, 378, 45, SOFT, LINE)
        page.rect(MARGIN + 10, top + 10, 24, 24, SENTRO_BLUE if index % 2 else SENTRO_INDIGO)
        page.text(MARGIN + 18, top + 15, index, 9, bold=True, color=WHITE)
        page.wrapped_text(MARGIN + 44, top + 10, step, 324, 8.5, max_lines=2)
        top += 52

    comparison_x = MARGIN + 398
    page.text(comparison_x, 72, "Scan comparison", 15, bold=True)
    page.rect(comparison_x, 100, 380, 208, WHITE, LINE)
    headers = [("Metric", 0), ("Latest", 180), ("Previous", 245), ("Delta", 320)]
    for label, offset in headers:
        page.text(comparison_x + 12 + offset, 115, label, 8, bold=True, color=MUTED)
    page.line(comparison_x + 10, 136, comparison_x + 370, 136)
    comparison = model.get("comparison") or []
    if comparison:
        for index, row in enumerate(comparison[:6]):
            row_top = 148 + (index * 27)
            page.text(comparison_x + 12, row_top, row.get("label"), 8.5)
            page.text(comparison_x + 192, row_top, row.get("current", 0), 8.5, bold=True)
            page.text(comparison_x + 257, row_top, row.get("prior", 0), 8.5)
            delta = int(row.get("delta") or 0)
            page.text(comparison_x + 332, row_top, f"{delta:+d}", 8.5, bold=True, color=RISK_COLORS["CRITICAL"] if delta > 0 else RISK_COLORS["LOW"])
    else:
        page.wrapped_text(comparison_x + 14, 154, "Run and save at least two scans to populate comparison.", 340, 9, color=MUTED, max_lines=2)

    page.text(comparison_x, 334, "Priority file queue", 15, bold=True)
    priority = model.get("priority_files") or []
    top = 362.0
    for index, row in enumerate(priority[:5], start=1):
        level = str(row.get("severity") or "LOW").upper()
        page.rect(comparison_x, top, 380, 31, RISK_SOFT.get(level, SOFT), LINE)
        page.text(comparison_x + 10, top + 9, f"{index:02d}", 8, bold=True, color=RISK_COLORS.get(level, SENTRO_BLUE))
        page.text(comparison_x + 38, top + 8, _clean(row.get("name"), 45), 8.5, bold=True)
        page.text(comparison_x + 294, top + 8, f"{level} {row.get('risk_score', 0)}", 8, bold=True, color=RISK_COLORS.get(level, SENTRO_BLUE))
        top += 36
    if not priority:
        page.text(comparison_x, top, "No priority files in this scope.", 9, color=MUTED)

    _page_footer(page, model, page_number)
    return page


def _evidence_pages(model: dict, first_page_number: int) -> list[_Page]:
    rows = list(model.get("evidence_register") or [])
    chunks = [rows[index:index + 8] for index in range(0, len(rows), 8)] or [[]]
    pages: list[_Page] = []
    for chunk_index, chunk in enumerate(chunks):
        page_number = first_page_number + chunk_index
        page = _Page()
        _page_header(page, model, "Evidence register", page_number)
        page.text(MARGIN, 70, "Full evidence register", 15, bold=True)
        page.text(MARGIN, 92, f"Scoped evidence rows {chunk_index * 8 + 1}-{chunk_index * 8 + len(chunk)} of {len(rows)}", 8.5, color=MUTED)
        columns = [
            ("File", 0, 220),
            ("Risk", 220, 80),
            ("Signals", 300, 190),
            ("Recommended action", 490, 288),
        ]
        page.rect(MARGIN, 116, CONTENT_WIDTH, 25, SENTRO_DEEP_BLUE)
        for label, offset, _width in columns:
            page.text(MARGIN + offset + 8, 124, label, 8, bold=True, color=WHITE)
        top = 141.0
        for row_index, row in enumerate(chunk):
            height = 48.0
            fill = WHITE if row_index % 2 == 0 else SOFT
            page.rect(MARGIN, top, CONTENT_WIDTH, height, fill, LINE)
            for _label, offset, _width in columns[1:]:
                page.line(MARGIN + offset, top, MARGIN + offset, top + height, LINE, 0.6)
            level = str(row.get("severity") or "LOW").upper()
            page.wrapped_text(MARGIN + 8, top + 8, row.get("name"), 204, 8.2, bold=True, max_lines=2)
            page.text(MARGIN + 228, top + 8, level, 8, bold=True, color=RISK_COLORS.get(level, SENTRO_BLUE))
            page.text(MARGIN + 228, top + 23, f"Score {row.get('risk_score', 0)}", 7.5, color=MUTED)
            page.wrapped_text(MARGIN + 308, top + 8, "; ".join(row.get("findings") or []) or "None", 174, 7.6, max_lines=3)
            page.wrapped_text(MARGIN + 498, top + 8, "; ".join(row.get("actions") or []) or "Review ownership and access", 272, 7.6, max_lines=3)
            top += height
        if not chunk:
            page.text(MARGIN + 8, 158, "No evidence rows match this report scope.", 9, color=MUTED)
        _page_footer(page, model, page_number)
        pages.append(page)
    return pages


def _pdf_text_object(value: str) -> bytes:
    text = _clean(value, 240)
    try:
        return b"(" + _pdf_escape(text).encode("latin-1") + b")"
    except UnicodeEncodeError:
        # A title in another script is written as UTF-16 with its byte-order mark,
        # the form a PDF text string takes when Latin-1 cannot hold it.
        return b"<FEFF" + text.encode("utf-16-be").hex().upper().encode("ascii") + b">"


def _info_object(model: dict) -> bytes:
    """The document information dictionary.

    Without it a reader has no name for the file and shows the storage filename -
    a 32-character hex id. This is where a report's title actually reaches the
    document: the window title, the properties pane, and what a print-to-file or
    a document management system indexes.
    """
    stamp = datetime.now(timezone.utc).strftime("D:%Y%m%d%H%M%SZ")
    fields = [
        (b"/Title", _pdf_text_object(_document_title(model))),
        (b"/Author", _pdf_text_object("SENTRO DSPM")),
        (b"/Subject", _pdf_text_object(f"Scan {model.get('scan_id', '')} - scope: {_scope_label(model)}")),
        (b"/Creator", _pdf_text_object(f"SENTRO DSPM ({REPORT_TEMPLATE_ID})")),
        (b"/Producer", _pdf_text_object("SENTRO DSPM report renderer")),
        (b"/CreationDate", b"(" + stamp.encode("ascii") + b")"),
        (b"/ModDate", b"(" + stamp.encode("ascii") + b")"),
    ]
    return b"<< " + b" ".join(key + b" " + value for key, value in fields) + b" >>"


def _build_pdf(pages: Iterable[_Page], model: dict | None = None) -> bytes:
    page_list = list(pages)
    page_numbers = [5 + (index * 2) for index in range(len(page_list))]
    # The embedded faces follow the pages and the information dictionary, five objects
    # each; their numbers are known before the pages that name them are written.
    fonts = _DOCUMENT_FONTS.get()
    first_font = 5 + (len(page_list) * 2) + 1
    font_resources = ""
    if fonts is not None:
        font_resources = f" /U0 {first_font} 0 R /U1 {first_font + 5} 0 R"
    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        f"<< /Type /Pages /Kids [{' '.join(f'{number} 0 R' for number in page_numbers)}] /Count {len(page_list)} >>".encode("ascii"),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
    ]
    for index, page in enumerate(page_list):
        page_number = 5 + (index * 2)
        content_number = page_number + 1
        stream = "\n".join(page.commands).encode("latin-1", "replace")
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_WIDTH:.0f} {PAGE_HEIGHT:.0f}] /Resources << /Font << /F1 3 0 R /F2 4 0 R{font_resources} >> >> /Contents {content_number} 0 R >>".encode("ascii")
        )
        objects.append(b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream")

    # Appended last so the fixed object numbers above (and the page arithmetic
    # that depends on them) stay exactly where they are.
    objects.append(_info_object(model or {}))
    info_number = len(objects)
    if fonts is not None:
        objects.extend(fonts.faces[False].pdf_objects(first_font))
        objects.extend(fonts.faces[True].pdf_objects(first_font + 5))

    payload = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: list[int] = [0]
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(payload))
        payload.extend(f"{number} 0 obj\n".encode("ascii"))
        payload.extend(obj)
        payload.extend(b"\nendobj\n")
    xref_offset = len(payload)
    payload.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    payload.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        payload.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    payload.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R /Info {info_number} 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    )
    return bytes(payload)


@contextmanager
def rendering(font_dir: Path | None = None) -> Iterator[_Fonts | None]:
    """The fonts one document is drawn and measured with, for the duration of the block:
    the embedded faces, or None (the Helvetica fallback) when either file is missing."""
    regular, bold = pdf_font.load(False, font_dir), pdf_font.load(True, font_dir)
    fonts = _Fonts(regular, bold) if regular is not None and bold is not None else None
    token = _DOCUMENT_FONTS.set(fonts)
    try:
        yield fonts
    finally:
        _DOCUMENT_FONTS.reset(token)


def render_visual_report_pdf(path: Path, model: dict, *, font_dir: Path | None = None) -> dict:
    """Render a Composer-aligned, scoped report and return artifact metadata."""
    with rendering(font_dir) as fonts:
        pages: list[_Page] = [_summary_page(model, 1), _operations_page(model, 2)]
        pages.extend(_evidence_pages(model, 3))
        path.write_bytes(_build_pdf(pages, model))
    evidence_count = len(model.get("evidence_register") or [])
    return {
        "render_style": "visual_composer",
        "template_id": REPORT_TEMPLATE_ID,
        "page_count": len(pages),
        "truncated": False,
        "original_line_count": evidence_count,
        "included_line_count": evidence_count,
        # Which face drew it: the embedded Unicode font, or the Latin-1 fallback that
        # transliterates when the font files are missing from the install.
        "font": "Inter (embedded, Unicode)" if fonts is not None else "Helvetica (Latin-1 fallback)",
    }
