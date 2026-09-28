"""C9: real Word and Excel reports, written on the server without a dependency.

The console's Word and Excel "reports" were HTML with a .doc or .xls name: Office opened
them only after warning that the file did not match its extension, Excel re-parsed every
cell (a file named `=HYPERLINK(...)` became a live formula unless the page remembered to
quote it), and the server never saw what left. These are Office Open XML packages - a
.docx and a .xlsx built with zipfile and XML - from the sections the Reports page
composed, and the server decides what is in them:

* every string passes the shared export masking (classification.masking.mask_in_text),
  the same pass the PDF uses, so a card number that reached a report as a file name is
  masked in all three formats;
* a workbook cell is typed. Text is an inline string, never a formula, and text that
  begins with a formula character also carries Excel's quote-prefix style, so editing
  the cell keeps it text; a figure is a number, so the sheet can be summed and pivoted;
* characters XML cannot carry are dropped rather than producing a file Office refuses.

`render_docx(report)` and `render_xlsx(report)` take the same dict:

    {"title": str, "lines": [str, ...],
     "blocks": [{"label": str,
                 "table": {"headers": [str, ...], "rows": [[cell, ...], ...]} | None,
                 "detail": [{"finding", "severity", "status", "file", "data_class", "owner",
                             "frameworks", "score", "occurrences", "due", "reason",
                             "recommendation"}, ...],
                 "paragraphs": [str, ...], "notes": [str, ...]}, ...]}

and return (bytes, stats) where stats counts sections, rows and masked values.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
from typing import Any, Iterable
from xml.sax.saxutils import escape as _xml_escape

from classification.masking import mask_in_text

DOCX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
XLSX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

EXCEL_CELL_LIMIT = 32767
EXCEL_SHEET_NAME_LIMIT = 31
# The four characters a spreadsheet treats as the start of a formula, plus the two
# whitespace characters Excel strips before deciding.
FORMULA_LEAD = re.compile(r"^[=+\-@\t\r]")
# XML 1.0 cannot carry these at all, escaped or not.
_XML_ILLEGAL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff￾￿]")
_SHEET_NAME_ILLEGAL = re.compile(r"[\[\]:*?/\\]")

DETAIL_COLUMNS = [
    ("#", None), ("Finding", "finding"), ("Severity", "severity"), ("Status", "status"),
    ("File", "file"), ("Data class", "data_class"), ("Owner", "owner"), ("Framework", "frameworks"),
    ("Score", "score"), ("Occurrences", "occurrences"), ("Due", "due"),
    ("Why it is a risk", "reason"), ("Recommended action", "recommendation"),
]
DETAIL_FACTS = [("Status", "status"), ("Data class", "data_class"), ("Framework", "frameworks"),
                ("Owner", "owner"), ("Score", "score"), ("Occurrences", "occurrences"), ("Due", "due")]


@dataclass
class _Text:
    """Every string on its way into a file: masked, made XML-safe, counted."""

    masked: int = 0

    def __call__(self, value: Any, limit: int | None = None) -> str:
        text, count = mask_in_text("" if value is None else value)
        self.masked += count
        text = _XML_ILLEGAL.sub("", text)
        if limit is not None and len(text) > limit:
            text = text[:limit - 1] + "…"
        return text


def _x(value: str) -> str:
    # A bare carriage return would be read back as a line feed (XML normalises line
    # ends); the character reference keeps the text exactly as it was.
    return _xml_escape(value, {'"': "&quot;", "\r": "&#13;"})


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _core_properties(title: str) -> str:
    stamp = _stamp()
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            f"<dc:title>{_x(title)}</dc:title><dc:creator>SENTRO DSPM</dc:creator>"
            "<cp:lastModifiedBy>SENTRO DSPM</cp:lastModifiedBy>"
            f'<dcterms:created xsi:type="dcterms:W3CDTF">{stamp}</dcterms:created>'
            f'<dcterms:modified xsi:type="dcterms:W3CDTF">{stamp}</dcterms:modified>'
            "</cp:coreProperties>")


def _app_properties(application: str) -> str:
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" '
            'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
            f"<Application>{_x(application)}</Application></Properties>")


def _package(parts: dict[str, str]) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as package:
        # [Content_Types].xml first: some readers sniff for it at the start of the archive.
        for name in sorted(parts, key=lambda item: (item != "[Content_Types].xml", item)):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            package.writestr(info, parts[name].encode("utf-8"))
    return buffer.getvalue()


def _blocks(report: dict) -> list[dict]:
    return [block for block in (report.get("blocks") or []) if isinstance(block, dict)]


def _detail_value(entry: dict, key: str) -> str:
    value = entry.get(key)
    return "" if value is None else str(value)


# ── Word ──────────────────────────────────────────────────────────────────────────
_W_NS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" ' \
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'


def _run(text: str, *, bold: bool = False, italic: bool = False) -> str:
    props = ("<w:b/>" if bold else "") + ("<w:i/>" if italic else "")
    return (f"<w:r>{f'<w:rPr>{props}</w:rPr>' if props else ''}"
            f'<w:t xml:space="preserve">{_x(text)}</w:t></w:r>')


def _paragraph(runs: str | Iterable[str], style: str | None = None, *, keep_next: bool = False) -> str:
    props = (f'<w:pStyle w:val="{style}"/>' if style else "") + ("<w:keepNext/>" if keep_next else "")
    body = runs if isinstance(runs, str) else "".join(runs)
    return f"<w:p>{f'<w:pPr>{props}</w:pPr>' if props else ''}{body}</w:p>"


def _word_table(headers: list[str], rows: list[list[str]]) -> str:
    def cell(text: str, header: bool) -> str:
        shading = '<w:shd w:val="clear" w:color="auto" w:fill="EEF2FF"/>' if header else ""
        return (f'<w:tc><w:tcPr><w:tcW w:w="0" w:type="auto"/>{shading}</w:tcPr>'
                f'{_paragraph(_run(text, bold=header), "TableText")}</w:tc>')

    header_row = ('<w:tr><w:trPr><w:tblHeader/><w:cantSplit/></w:trPr>'
                  + "".join(cell(text, True) for text in headers) + "</w:tr>")
    body = "".join("<w:tr><w:trPr><w:cantSplit/></w:trPr>" + "".join(cell(text, False) for text in row) + "</w:tr>"
                   for row in rows)
    grid = "".join('<w:gridCol w:w="1000"/>' for _ in headers)
    return ('<w:tbl><w:tblPr><w:tblStyle w:val="SentroTable"/><w:tblW w:w="5000" w:type="pct"/>'
            '<w:tblLook w:val="04A0" w:firstRow="1" w:lastRow="0" w:firstColumn="0" w:lastColumn="0" '
            'w:noHBand="0" w:noVBand="1"/></w:tblPr>'
            f"<w:tblGrid>{grid}</w:tblGrid>{header_row}{body}</w:tbl>")


def _word_body(report: dict, text: _Text) -> tuple[str, dict]:
    parts = [_paragraph(_run(text(report.get("title") or "SENTRO report", 500)), "Title")]
    for line in report.get("lines") or []:
        if str(line or "").strip():
            parts.append(_paragraph(_run(text(line, 2000)), "Subtitle"))
    rows = 0
    for number, block in enumerate(_blocks(report), start=1):
        parts.append(_paragraph(_run(f"{number}. {text(block.get('label'), 300)}"), "Heading1", keep_next=True))
        for paragraph in block.get("paragraphs") or []:
            parts.append(_paragraph(_run(text(paragraph, EXCEL_CELL_LIMIT))))
        table = block.get("table") or None
        if table and table.get("headers"):
            headers = [text(head, 200) for head in table["headers"]]
            body = [[text(cell, EXCEL_CELL_LIMIT) for cell in (row or [])][:len(headers)]
                    + [""] * max(0, len(headers) - len(row or [])) for row in table.get("rows") or []]
            rows += len(body)
            parts.append(_word_table(headers, body))
        for index, entry in enumerate(block.get("detail") or [], start=1):
            rows += 1
            heading = text(entry.get("finding") or "Finding", 300)
            severity = text(entry.get("severity"), 40)
            parts.append(_paragraph(_run(f"{index}. {heading}" + (f" — {severity}" if severity else "")),
                                    "Heading2", keep_next=True))
            if entry.get("file"):
                parts.append(_paragraph(_run(text(entry.get("file"), 2000), italic=True), keep_next=True))
            facts = [(term, text(_detail_value(entry, key), 500)) for term, key in DETAIL_FACTS]
            facts = [(term, value) for term, value in facts if value.strip()]
            if facts:
                runs = []
                for position, (term, value) in enumerate(facts):
                    if position:
                        runs.append(_run("  ·  "))
                    runs.append(_run(f"{term}: ", bold=True))
                    runs.append(_run(value))
                parts.append(_paragraph(runs))
            for lead, key in (("Why it is a risk. ", "reason"), ("Recommended action. ", "recommendation")):
                value = text(_detail_value(entry, key), EXCEL_CELL_LIMIT)
                if value.strip():
                    parts.append(_paragraph([_run(lead, bold=True), _run(value)]))
        for note in block.get("notes") or []:
            if str(note or "").strip():
                parts.append(_paragraph(_run(text(note, 2000), italic=True), "Note"))
    section = ('<w:sectPr><w:footerReference w:type="default" r:id="rIdFooter"/>'
               '<w:pgSz w:w="16838" w:h="11906" w:orient="landscape"/>'
               '<w:pgMar w:top="850" w:right="850" w:bottom="850" w:left="850" w:header="567" w:footer="567" w:gutter="0"/>'
               "</w:sectPr>")
    document = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                f"<w:document {_W_NS}><w:body>{''.join(parts)}{section}</w:body></w:document>")
    return document, {"sections": len(_blocks(report)), "rows": rows}


_WORD_STYLES = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles {_W_NS}>
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="Calibri" w:cs="Calibri"/><w:sz w:val="20"/><w:szCs w:val="20"/><w:lang w:val="en-GB"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="100" w:line="264" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:next w:val="Subtitle"/><w:qFormat/><w:pPr><w:spacing w:after="60"/></w:pPr><w:rPr><w:b/><w:color w:val="0B1739"/><w:sz w:val="40"/><w:szCs w:val="40"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/><w:basedOn w:val="Normal"/><w:qFormat/><w:pPr><w:spacing w:after="40"/></w:pPr><w:rPr><w:color w:val="4B5563"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:pPr><w:keepNext/><w:pBdr><w:bottom w:val="single" w:sz="4" w:space="2" w:color="D1D5DB"/></w:pBdr><w:spacing w:before="360" w:after="120"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:color w:val="102A56"/><w:sz w:val="28"/><w:szCs w:val="28"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:pPr><w:keepNext/><w:spacing w:before="240" w:after="60"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:b/><w:color w:val="1F2937"/><w:sz w:val="23"/><w:szCs w:val="23"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="TableText"><w:name w:val="Table Text"/><w:basedOn w:val="Normal"/><w:qFormat/><w:pPr><w:spacing w:after="0" w:line="240" w:lineRule="auto"/></w:pPr><w:rPr><w:sz w:val="17"/><w:szCs w:val="17"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Note"><w:name w:val="Note"/><w:basedOn w:val="Normal"/><w:qFormat/><w:rPr><w:i/><w:color w:val="4B5563"/><w:sz w:val="18"/><w:szCs w:val="18"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Footer"><w:name w:val="footer"/><w:basedOn w:val="Normal"/><w:rPr><w:color w:val="6B7280"/><w:sz w:val="16"/><w:szCs w:val="16"/></w:rPr></w:style>
<w:style w:type="table" w:default="1" w:styleId="TableNormal"><w:name w:val="Normal Table"/><w:tblPr><w:tblInd w:w="0" w:type="dxa"/><w:tblCellMar><w:top w:w="0" w:type="dxa"/><w:left w:w="108" w:type="dxa"/><w:bottom w:w="0" w:type="dxa"/><w:right w:w="108" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>
<w:style w:type="table" w:styleId="SentroTable"><w:name w:val="Sentro Table"/><w:basedOn w:val="TableNormal"/><w:tblPr><w:tblBorders><w:top w:val="single" w:sz="4" w:space="0" w:color="D1D5DB"/><w:left w:val="single" w:sz="4" w:space="0" w:color="D1D5DB"/><w:bottom w:val="single" w:sz="4" w:space="0" w:color="D1D5DB"/><w:right w:val="single" w:sz="4" w:space="0" w:color="D1D5DB"/><w:insideH w:val="single" w:sz="4" w:space="0" w:color="D1D5DB"/><w:insideV w:val="single" w:sz="4" w:space="0" w:color="D1D5DB"/></w:tblBorders><w:tblCellMar><w:top w:w="40" w:type="dxa"/><w:left w:w="80" w:type="dxa"/><w:bottom w:w="40" w:type="dxa"/><w:right w:w="80" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>
</w:styles>"""


def _word_footer(title: str) -> str:
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            f"<w:ftr {_W_NS}><w:p><w:pPr><w:pStyle w:val=\"Footer\"/></w:pPr>"
            f"{_run(f'SENTRO DSPM · {title} · page ')}"
            '<w:r><w:fldChar w:fldCharType="begin"/></w:r>'
            '<w:r><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r>'
            '<w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>1</w:t></w:r>'
            '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p></w:ftr>')


def render_docx(report: dict) -> tuple[bytes, dict]:
    text = _Text()
    title = text(report.get("title") or "SENTRO report", 500)
    document, stats = _word_body(report, text)
    parts = {
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
            '<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>'
            '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
            '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
            "</Types>"),
        "_rels/.rels": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
            '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
            "</Relationships>"),
        "word/_rels/document.xml.rels": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
            '<Relationship Id="rIdFooter" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>'
            "</Relationships>"),
        "word/document.xml": document,
        "word/styles.xml": _WORD_STYLES,
        "word/footer1.xml": _word_footer(title),
        "docProps/core.xml": _core_properties(title),
        "docProps/app.xml": _app_properties("SENTRO DSPM"),
    }
    return _package(parts), {**stats, "masked_values": text.masked}


# ── Excel ─────────────────────────────────────────────────────────────────────────
# Cell styles, by index into cellXfs below.
(_XF_DEFAULT, _XF_HEADER, _XF_TITLE, _XF_TEXT_QUOTED, _XF_WRAP, _XF_WRAP_QUOTED, _XF_PERCENT, _XF_INTEGER,
 _XF_DECIMAL, _XF_MUTED) = range(10)

_XLSX_STYLES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<numFmts count="1"><numFmt numFmtId="164" formatCode="#,##0.##"/></numFmts>
<fonts count="4"><font><sz val="11"/><name val="Calibri"/><family val="2"/></font><font><b/><sz val="11"/><name val="Calibri"/><family val="2"/></font><font><b/><sz val="14"/><color rgb="FF0B1739"/><name val="Calibri"/><family val="2"/></font><font><i/><sz val="10"/><color rgb="FF4B5563"/><name val="Calibri"/><family val="2"/></font></fonts>
<fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FFEEF2FF"/><bgColor indexed="64"/></patternFill></fill></fills>
<borders count="2"><border><left/><right/><top/><bottom/><diagonal/></border><border><left/><right/><top/><bottom style="thin"><color rgb="FFC7D2FE"/></bottom><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="10">
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
<xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"/>
<xf numFmtId="0" fontId="2" fillId="0" borderId="0" xfId="0" applyFont="1"/>
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" quotePrefix="1"/>
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" quotePrefix="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="9" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/>
<xf numFmtId="3" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/>
<xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/>
<xf numFmtId="0" fontId="3" fillId="0" borderId="0" xfId="0" applyFont="1"/>
</cellXfs>
<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>"""

# A figure the page printed as text ("1,204", "37.5", "12%") becomes a number, so the
# sheet sums and pivots. Not an identifier: a leading zero or more than 15 digits (all
# a spreadsheet keeps exactly) stays text, or "0042" would print as 42.
_INTEGER = re.compile(r"-?(?:0|[1-9]\d{0,2}(?:,\d{3})+|[1-9]\d*)")
_DECIMAL = re.compile(r"-?(?:0|[1-9]\d{0,2}(?:,\d{3})+|[1-9]\d*)\.\d+")
_PERCENT = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?%")
_EXACT_DIGITS = 15


def _column_letter(index: int) -> str:
    letters = ""
    index += 1
    while index:
        index, remainder = divmod(index - 1, 26)
        letters = chr(65 + remainder) + letters
    return letters


def _figure(value: Any) -> tuple[float | int, int] | None:
    """(number, cell style) when `value` is a figure, else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return (value, _XF_INTEGER) if len(str(abs(value))) <= _EXACT_DIGITS else None
    if isinstance(value, float):
        return (value, _XF_DECIMAL) if value == value and abs(value) != float("inf") else None
    text = str(value if value is not None else "").strip()
    if len(re.sub(r"\D", "", text)) > _EXACT_DIGITS:
        return None
    if _INTEGER.fullmatch(text):
        return int(text.replace(",", "")), _XF_INTEGER
    if _DECIMAL.fullmatch(text):
        return float(text.replace(",", "")), _XF_DECIMAL
    if _PERCENT.fullmatch(text):
        return float(text[:-1]) / 100, _XF_PERCENT
    return None


class _Sheet:
    def __init__(self, name: str, text: _Text) -> None:
        self.name = name
        self.text = text
        self.rows: list[str] = []
        self.widths: dict[int, int] = {}
        self.table: tuple[int, int] | None = None  # (columns, last row) of the filterable table

    def add(self, cells: list[Any], *, style: int | None = None, wrap_from: int = 60) -> None:
        number = len(self.rows) + 1
        out = []
        for column, value in enumerate(cells):
            reference = f"{_column_letter(column)}{number}"
            figure = _figure(value) if style is None else None
            if figure is not None:
                amount, xf = figure
                out.append(f'<c r="{reference}" s="{xf}"><v>{amount!r}</v></c>')
                self._width(column, len(str(value)))
                continue
            text = self.text("" if value is None else value, EXCEL_CELL_LIMIT)
            if not text:
                continue
            # Never a formula: text is an inline string, which Excel does not evaluate.
            # Text that LOOKS like one also carries the quote prefix, so editing the
            # cell and pressing Enter keeps it text instead of running it.
            quoted = bool(FORMULA_LEAD.match(text))
            if style is not None:
                xf = style
            elif len(text) > wrap_from:
                xf = _XF_WRAP_QUOTED if quoted else _XF_WRAP
            else:
                xf = _XF_TEXT_QUOTED if quoted else _XF_DEFAULT
            styled = f' s="{xf}"' if xf else ""
            out.append(f'<c r="{reference}" t="inlineStr"{styled}><is><t xml:space="preserve">{_x(text)}</t></is></c>')
            self._width(column, min(len(text), wrap_from))
        self.rows.append(f'<row r="{number}">{"".join(out)}</row>')

    def blank(self) -> None:
        self.rows.append(f'<row r="{len(self.rows) + 1}"/>')

    def _width(self, column: int, length: int) -> None:
        self.widths[column] = max(self.widths.get(column, 0), length)

    @property
    def filter_ref(self) -> str | None:
        if not self.table:
            return None
        columns, last = self.table
        return f"$A$1:${_column_letter(columns - 1)}${last}"

    def xml(self) -> str:
        views = '<sheetViews><sheetView workbookViewId="0"/></sheetViews>'
        filters = ""
        if self.table:
            # The header row stays in view and every column filters, which is what makes a
            # section a table a reader can slice rather than a printout.
            views = ('<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" '
                     'activePane="bottomLeft" state="frozen"/><selection pane="bottomLeft" activeCell="A2" sqref="A2"/>'
                     "</sheetView></sheetViews>")
            filters = f'<autoFilter ref="{self.filter_ref.replace("$", "")}"/>'
        cols = "".join(
            f'<col min="{column + 1}" max="{column + 1}" width="{max(8, min(width, 60)) + 2}" customWidth="1"/>'
            for column, width in sorted(self.widths.items()))
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                f"{views}<sheetFormatPr defaultRowHeight=\"15\"/>{f'<cols>{cols}</cols>' if cols else ''}"
                f"<sheetData>{''.join(self.rows)}</sheetData>{filters}</worksheet>")


def _sheet_name(label: str, used: set[str]) -> str:
    """A name Excel accepts: at most 31 characters, none of []:*?/\\, no edge apostrophe,
    not the reserved "History", unique ignoring case."""
    base = _SHEET_NAME_ILLEGAL.sub(" ", _XML_ILLEGAL.sub("", label))
    base = re.sub(r"\s+", " ", base).strip().strip("'")[:EXCEL_SHEET_NAME_LIMIT].strip() or "Section"
    if base.lower() == "history":
        base = "History (report)"
    name, counter = base, 2
    while name.lower() in used:
        suffix = f" ({counter})"
        name = base[:EXCEL_SHEET_NAME_LIMIT - len(suffix)].rstrip() + suffix
        counter += 1
    used.add(name.lower())
    return name


def _section_sheet(number: int, block: dict, text: _Text, used: set[str]) -> tuple[_Sheet, str, int]:
    label = text(block.get("label"), 300) or f"Section {number}"
    sheet = _Sheet(_sheet_name(f"{number}. {label}", used), text)
    count = 0
    table = block.get("table") or None
    if table and table.get("headers"):
        headers = list(table["headers"])
        sheet.add(headers, style=_XF_HEADER)
        for row in table.get("rows") or []:
            sheet.add(list(row or [])[:len(headers)])
            count += 1
        sheet.table = (len(headers), len(sheet.rows))
    elif block.get("detail"):
        sheet.add([head for head, _key in DETAIL_COLUMNS], style=_XF_HEADER)
        for index, entry in enumerate(block["detail"], start=1):
            sheet.add([index, *(_detail_value(entry, key) for _head, key in DETAIL_COLUMNS[1:])])
            count += 1
        sheet.table = (len(DETAIL_COLUMNS), len(sheet.rows))
    paragraphs = [value for value in (block.get("paragraphs") or []) if str(value or "").strip()]
    notes = [value for value in (block.get("notes") or []) if str(value or "").strip()]
    for lines, style, wrap_from in ((paragraphs, None, 120), (notes, _XF_MUTED, 60)):
        if lines and sheet.rows:
            sheet.blank()
        for line in lines:
            sheet.add([line], style=style, wrap_from=wrap_from)
    if not sheet.rows:
        sheet.add([label])
    return sheet, label, count


def render_xlsx(report: dict) -> tuple[bytes, dict]:
    text = _Text()
    title = text(report.get("title") or "SENTRO report", 500)
    used: set[str] = set()
    summary = _Sheet(_sheet_name("Summary", used), text)
    summary.add([title], style=_XF_TITLE)
    for line in report.get("lines") or []:
        if str(line or "").strip():
            summary.add([line], style=_XF_MUTED)
    summary.blank()
    summary.add(["#", "Section", "Sheet", "Rows"], style=_XF_HEADER)

    sections: list[_Sheet] = []
    rows = 0
    for number, block in enumerate(_blocks(report), start=1):
        sheet, label, count = _section_sheet(number, block, text, used)
        sections.append(sheet)
        summary.add([number, label, sheet.name, count])
        rows += count
    sheets = [summary, *sections]

    workbook_sheets = "".join(f'<sheet name="{_x(sheet.name)}" sheetId="{index}" r:id="rIdSheet{index}"/>'
                              for index, sheet in enumerate(sheets, start=1))
    # Excel records every autofilter's range under this hidden name; a file without it
    # opens, but Excel repairs the filter on first save.
    defined = "".join(
        f'<definedName name="_xlnm._FilterDatabase" localSheetId="{index}" hidden="1">'
        f"{_x(_quoted_sheet(sheet.name))}!{sheet.filter_ref}</definedName>"
        for index, sheet in enumerate(sheets) if sheet.filter_ref)
    parts = {
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
            + "".join(f'<Override PartName="/xl/worksheets/sheet{index}.xml" '
                      'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
                      for index in range(1, len(sheets) + 1))
            + '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
            '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
            "</Types>"),
        "_rels/.rels": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
            '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
            "</Relationships>"),
        "xl/workbook.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<bookViews><workbookView activeTab="0"/></bookViews>'
            f"<sheets>{workbook_sheets}</sheets>{f'<definedNames>{defined}</definedNames>' if defined else ''}</workbook>"),
        "xl/_rels/workbook.xml.rels": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            + "".join(f'<Relationship Id="rIdSheet{index}" '
                      'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
                      f'Target="worksheets/sheet{index}.xml"/>' for index in range(1, len(sheets) + 1))
            + '<Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
            "</Relationships>"),
        "xl/styles.xml": _XLSX_STYLES,
        "docProps/core.xml": _core_properties(title),
        "docProps/app.xml": _app_properties("SENTRO DSPM"),
    }
    for index, sheet in enumerate(sheets, start=1):
        parts[f"xl/worksheets/sheet{index}.xml"] = sheet.xml()
    return _package(parts), {"sections": len(sections), "rows": rows, "masked_values": text.masked}


def _quoted_sheet(name: str) -> str:
    return "'" + name.replace("'", "''") + "'"
