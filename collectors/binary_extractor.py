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
        parts = [name for name in archive.namelist() if name.startswith("xl/") and name.endswith(".xml")]
        return "\n".join(_xml_text(archive.read(name)) for name in parts)[:max_chars]


def _extract_pptx(path: Path, max_chars: int) -> str:
    with zipfile.ZipFile(path) as archive:
        parts = [name for name in archive.namelist() if name.startswith("ppt/slides/") and name.endswith(".xml")]
        return "\n".join(_xml_text(archive.read(name)) for name in parts)[:max_chars]


def _extract_odt(path: Path, max_chars: int) -> str:
    with zipfile.ZipFile(path) as archive:
        parts = [name for name in archive.namelist() if name.endswith(".xml")]
        return "\n".join(_xml_text(archive.read(name)) for name in parts)[:max_chars]


def _extract_pdf_light(path: Path, max_chars: int) -> str:
    data = path.read_bytes()[: max_chars * 4]
    chunks = re.findall(rb"\(([^()]*)\)", data)
    return "\n".join(chunk.decode("latin-1", errors="ignore") for chunk in chunks)[:max_chars]
