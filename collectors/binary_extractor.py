from __future__ import annotations

import re
import zipfile
from pathlib import Path
from xml.etree import ElementTree  # Element type + navigation only

# M8: parse untrusted document XML with defusedxml, which blocks entity-expansion
# (billion-laughs), XXE, and external-DTD attacks that the stdlib parser accepts.
import defusedxml.ElementTree as _DefusedET


BINARY_TEXT_EXTENSIONS = {
    ".docm",
    ".docx",
    ".dotm",
    ".dotx",
    ".odp",
    ".ods",
    ".odt",
    ".otp",
    ".pdf",
    ".pptm",
    ".pptx",
    ".xlsm",
    ".xlsx",
}

# M8: bound Office/ODT extraction so a hostile document cannot exhaust memory.
# The per-part DECOMPRESSED read cap is the real OOM guard - a zip-bomb part is
# never inflated in full. The ratio check rejects an obvious bomb before reading;
# the total-bytes and parts caps bound a document assembled from many parts.
MAX_DOC_ENTRY_BYTES = 50 * 1024 * 1024      # 50 MB per XML part (decompressed)
MAX_DOC_TOTAL_BYTES = 200 * 1024 * 1024     # 200 MB total decompressed per document
MAX_DOC_COMPRESSION_RATIO = 200             # skip a part that inflates beyond this
MAX_DOC_PARTS = 4096                         # cap the number of parts processed


def extract_binary_text(path: Path, max_chars: int = 120_000) -> str:
    return extract_binary_text_with_status(path, max_chars)[0]


def extract_binary_text_with_status(path: Path, max_chars: int = 120_000) -> tuple[str, str]:
    """(text, why there is none). The reason is "" when text came out (or the document
    holds none), "no_text_layer" for a PDF with no text to extract - a scan, images only -
    "password_protected" for one that does not open without a password, and
    "not_extracted" when the document could not be parsed at all."""
    suffix = path.suffix.lower()
    try:
        if suffix in {".docm", ".docx", ".dotm", ".dotx"}:
            return _extract_docx(path, max_chars), ""
        if suffix in {".xlsm", ".xlsx"}:
            return _extract_xlsx(path, max_chars), ""
        if suffix in {".pptm", ".pptx"}:
            return _extract_pptx(path, max_chars), ""
        if suffix in {".odp", ".ods", ".odt", ".otp"}:
            return _extract_odt(path, max_chars), ""
        if suffix == ".pdf":
            return _extract_pdf(path, max_chars)
    except Exception:
        return "", "not_extracted"
    return "", ""


def _parse_xml(data: bytes):
    """Parse XML defensively (defusedxml blocks billion-laughs / XXE / external-DTD).
    Returns the root Element, or None on any parse error or blocked attack."""
    if not data:
        return None
    try:
        return _DefusedET.fromstring(data)
    except Exception:
        return None


def _read_zip_member(archive: zipfile.ZipFile, name: str, max_bytes: int = MAX_DOC_ENTRY_BYTES) -> bytes:
    """Read a zip member under a hard DECOMPRESSED byte cap plus a compression-ratio
    guard, so a zip-bomb / multi-GB-inflating part cannot exhaust memory. Returns the
    (possibly truncated) bytes, or b"" if the member is missing or looks like a bomb."""
    try:
        info = archive.getinfo(name)
    except KeyError:
        return b""
    # Reject a part that declares implausible inflation, before reading anything.
    if info.compress_size > 0 and (info.file_size / info.compress_size) > MAX_DOC_COMPRESSION_RATIO:
        return b""
    # Read at most max_bytes DECOMPRESSED, so a lying header cannot OOM us either.
    try:
        with archive.open(name) as handle:
            data = handle.read(max_bytes + 1)
    except Exception:
        return b""
    return data[:max_bytes]


def _xml_text(data: bytes) -> str:
    root = _parse_xml(data)
    if root is None:
        return ""
    return " ".join(node.text or "" for node in root.iter() if node.text)


def _join_xml_parts(archive: zipfile.ZipFile, parts: list[str], max_chars: int) -> str:
    """Text-extract each XML part under total-bytes / parts / char budgets, stopping
    early so a document made of many (or bomb) parts stays bounded."""
    out: list[str] = []
    total_bytes = 0
    chars = 0
    for name in parts[:MAX_DOC_PARTS]:
        data = _read_zip_member(archive, name)
        total_bytes += len(data)
        text = _xml_text(data)
        if text:
            out.append(text)
            chars += len(text) + 1
        if chars >= max_chars or total_bytes >= MAX_DOC_TOTAL_BYTES:
            break
    return "\n".join(out)[:max_chars]


def _extract_docx(path: Path, max_chars: int) -> str:
    with zipfile.ZipFile(path) as archive:
        parts = [name for name in archive.namelist() if name.startswith("word/") and name.endswith(".xml")]
        return _join_xml_parts(archive, parts, max_chars)


def _extract_xlsx(path: Path, max_chars: int) -> str:
    with zipfile.ZipFile(path) as archive:
        shared_strings = _xlsx_shared_strings(archive)
        sheet_names = _xlsx_sheet_names(archive)
        sheet_parts = [
            name
            for name in archive.namelist()
            if re.fullmatch(r"xl/worksheets/sheet\d+\.xml", name)
        ]
        lines: list[str] = []
        total_bytes = 0
        for index, name in enumerate(sorted(sheet_parts)[:MAX_DOC_PARTS], start=1):
            sheet_name = sheet_names.get(name, f"Sheet{index}")
            data = _read_zip_member(archive, name)
            total_bytes += len(data)
            lines.extend(_xlsx_sheet_text(data, sheet_name, shared_strings))
            if len("\n".join(lines)) >= max_chars or total_bytes >= MAX_DOC_TOTAL_BYTES:
                break
        return "\n".join(lines)[:max_chars]


def _extract_pptx(path: Path, max_chars: int) -> str:
    with zipfile.ZipFile(path) as archive:
        parts = [name for name in archive.namelist() if name.startswith("ppt/slides/") and name.endswith(".xml")]
        return _join_xml_parts(archive, parts, max_chars)


def _extract_odt(path: Path, max_chars: int) -> str:
    with zipfile.ZipFile(path) as archive:
        parts = [name for name in archive.namelist() if name.endswith(".xml")]
        return _join_xml_parts(archive, parts, max_chars)


def _extract_pdf(path: Path, max_chars: int) -> tuple[str, str]:
    """The text of a PDF's pages, and why there is none when there is none.

    There used to be a fallback when pypdf found no text: a regex over the raw bytes for
    every "(...)" literal. What that finds is the uncompressed metadata - Title, Producer -
    never page text, which is compressed: a blank scan titled "Scanned passport" came out
    as "pypdf / Scanned passport", scanned and FULL, and an encrypted PDF took the same
    path and came back "scanned" instead of protected. A PDF without a text layer is now
    said to be one, and the file is read from its handle - not loaded whole - so its size
    does not decide the memory a scan takes."""
    try:
        from pypdf import PasswordType, PdfReader
    except ModuleNotFoundError:
        return "", "not_extracted"
    try:
        with path.open("rb") as handle:
            reader = PdfReader(handle)
            if reader.is_encrypted:
                # An empty user password opens a PDF that is only restricted, not sealed.
                try:
                    opened = reader.decrypt("") != PasswordType.NOT_DECRYPTED
                except Exception:
                    opened = False
                if not opened:
                    return "", "password_protected"
            parts: list[str] = []
            for page_number, page in enumerate(reader.pages, start=1):
                text = page.extract_text() or ""
                if text.strip():
                    parts.append(f"[pdf page={page_number}]\n{text}")
                if len("\n".join(parts)) >= max_chars:
                    break
    except Exception:
        return "", "not_extracted"
    text = "\n".join(parts)[:max_chars]
    return text, "" if text else "no_text_layer"


def _xlsx_shared_strings(archive: zipfile.ZipFile) -> list[str]:
    root = _parse_xml(_read_zip_member(archive, "xl/sharedStrings.xml"))
    if root is None:
        return []
    values: list[str] = []
    for item in _children_with_local_name(root, "si"):
        values.append("".join(node.text or "" for node in item.iter() if _local_name(node.tag) == "t"))
    return values


def _xlsx_sheet_names(archive: zipfile.ZipFile) -> dict[str, str]:
    workbook = _parse_xml(_read_zip_member(archive, "xl/workbook.xml"))
    rels = _parse_xml(_read_zip_member(archive, "xl/_rels/workbook.xml.rels"))
    if workbook is None or rels is None:
        return {}
    rel_targets: dict[str, str] = {}
    for rel in rels.iter():
        if _local_name(rel.tag) != "Relationship":
            continue
        rel_id = rel.attrib.get("Id", "")
        target = rel.attrib.get("Target", "").lstrip("/")
        if rel_id and target:
            rel_targets[rel_id] = target if target.startswith("xl/") else f"xl/{target}"
    names: dict[str, str] = {}
    for sheet in workbook.iter():
        if _local_name(sheet.tag) != "sheet":
            continue
        rel_id = sheet.attrib.get("{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id", "")
        target = rel_targets.get(rel_id, "")
        if target:
            names[target] = sheet.attrib.get("name", "") or Path(target).stem
    return names


def _xlsx_sheet_text(xml: bytes, sheet_name: str, shared_strings: list[str]) -> list[str]:
    root = _parse_xml(xml)
    if root is None:
        return []
    rows: list[str] = []
    for row in root.iter():
        if _local_name(row.tag) != "row":
            continue
        row_number = row.attrib.get("r", "")
        cells: list[str] = []
        for cell in row:
            if _local_name(cell.tag) != "c":
                continue
            value = _xlsx_cell_value(cell, shared_strings)
            if value:
                cells.append(f"{cell.attrib.get('r', '')}={value}")
        if cells:
            rows.append(f"[xlsx sheet={sheet_name} row={row_number}] " + " | ".join(cells))
    return rows


def _xlsx_cell_value(cell: ElementTree.Element, shared_strings: list[str]) -> str:
    cell_type = cell.attrib.get("t", "")
    if cell_type == "inlineStr":
        return " ".join(node.text or "" for node in cell.iter() if _local_name(node.tag) == "t").strip()
    value = ""
    for child in cell:
        if _local_name(child.tag) == "v":
            value = child.text or ""
            break
    if cell_type == "s":
        try:
            return shared_strings[int(value)].strip()
        except (ValueError, IndexError):
            return ""
    return value.strip()


def _children_with_local_name(root: ElementTree.Element, name: str) -> list[ElementTree.Element]:
    return [node for node in root if _local_name(node.tag) == name]


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]
