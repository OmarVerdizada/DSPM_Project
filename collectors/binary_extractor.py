from __future__ import annotations

import re
import zipfile
from pathlib import Path
from xml.etree import ElementTree


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


def extract_binary_text(path: Path, max_chars: int = 120_000) -> str:
    suffix = path.suffix.lower()
    try:
        if suffix in {".docm", ".docx", ".dotm", ".dotx"}:
            return _extract_docx(path, max_chars)
        if suffix in {".xlsm", ".xlsx"}:
            return _extract_xlsx(path, max_chars)
        if suffix in {".pptm", ".pptx"}:
            return _extract_pptx(path, max_chars)
        if suffix in {".odp", ".ods", ".odt", ".otp"}:
            return _extract_odt(path, max_chars)
        if suffix == ".pdf":
            return _extract_pdf_light(path, max_chars)
    except Exception:
        return ""
    return ""


def _xml_text(xml: bytes) -> str:
    root = ElementTree.fromstring(xml)
    return " ".join(node.text or "" for node in root.iter() if node.text)


def _extract_docx(path: Path, max_chars: int) -> str:
    with zipfile.ZipFile(path) as archive:
        parts = [name for name in archive.namelist() if name.startswith("word/") and name.endswith(".xml")]
        return "\n".join(_xml_text(archive.read(name)) for name in parts)[:max_chars]


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
        for index, name in enumerate(sorted(sheet_parts), start=1):
            sheet_name = sheet_names.get(name, f"Sheet{index}")
            lines.extend(_xlsx_sheet_text(archive.read(name), sheet_name, shared_strings))
            if len("\n".join(lines)) >= max_chars:
                break
        return "\n".join(lines)[:max_chars]


def _extract_pptx(path: Path, max_chars: int) -> str:
    with zipfile.ZipFile(path) as archive:
        parts = [name for name in archive.namelist() if name.startswith("ppt/slides/") and name.endswith(".xml")]
        return "\n".join(_xml_text(archive.read(name)) for name in parts)[:max_chars]


def _extract_odt(path: Path, max_chars: int) -> str:
    with zipfile.ZipFile(path) as archive:
        parts = [name for name in archive.namelist() if name.endswith(".xml")]
        return "\n".join(_xml_text(archive.read(name)) for name in parts)[:max_chars]


def _extract_pdf_light(path: Path, max_chars: int) -> str:
    parsed = _extract_pdf_with_pypdf(path, max_chars)
    if parsed:
        return parsed[:max_chars]
    data = path.read_bytes()[: max_chars * 4]
    chunks = re.findall(rb"\(([^()]*)\)", data)
    return "\n".join(chunk.decode("latin-1", errors="ignore") for chunk in chunks)[:max_chars]


def _extract_pdf_with_pypdf(path: Path, max_chars: int) -> str:
    try:
        from pypdf import PdfReader
    except ModuleNotFoundError:
        return ""
    try:
        reader = PdfReader(str(path))
        if reader.is_encrypted:
            try:
                reader.decrypt("")
            except Exception:
                return ""
        parts: list[str] = []
        for page_number, page in enumerate(reader.pages, start=1):
            text = page.extract_text() or ""
            if text.strip():
                parts.append(f"[pdf page={page_number}]\n{text}")
            if len("\n".join(parts)) >= max_chars:
                break
        return "\n".join(parts)
    except Exception:
        return ""


def _xlsx_shared_strings(archive: zipfile.ZipFile) -> list[str]:
    if "xl/sharedStrings.xml" not in archive.namelist():
        return []
    try:
        root = ElementTree.fromstring(archive.read("xl/sharedStrings.xml"))
    except ElementTree.ParseError:
        return []
    values: list[str] = []
    for item in _children_with_local_name(root, "si"):
        values.append("".join(node.text or "" for node in item.iter() if _local_name(node.tag) == "t"))
    return values


def _xlsx_sheet_names(archive: zipfile.ZipFile) -> dict[str, str]:
    try:
        workbook = ElementTree.fromstring(archive.read("xl/workbook.xml"))
        rels = ElementTree.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
    except (KeyError, ElementTree.ParseError):
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
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError:
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
