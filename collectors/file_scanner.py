from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from collectors.binary_extractor import BINARY_TEXT_EXTENSIONS, extract_binary_text


TEXT_EXTENSIONS = {
    ".txt",
    ".log",
    ".csv",
    ".tsv",
    ".json",
    ".xml",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".properties",
    ".env",
    ".bak",
    ".sql",
    ".dump",
    ".ps1",
    ".sh",
    ".bat",
    ".cmd",
    ".py",
    ".java",
    ".cs",
    ".go",
    ".rb",
    ".php",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".html",
    ".css",
    ".scss",
    ".md",
}

SCANNABLE_EXTENSIONS = TEXT_EXTENSIONS | BINARY_TEXT_EXTENSIONS


def normalize_extension_filter(extensions: Iterable[str] | None) -> set[str]:
    normalized: set[str] = set()
    for item in extensions or []:
        extension = item.strip().lower()
        if not extension:
            continue
        if not extension.startswith("."):
            extension = f".{extension}"
        normalized.add(extension)
    return normalized


@dataclass(slots=True)
class FileRecord:
    source: str
    path: str
    name: str
    size: int
    extension: str
    is_dir: bool = False
    is_hidden: bool = False
    share: str | None = None
    content: str = ""
    acl: dict | None = None

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "share": self.share,
            "path": self.path,
            "name": self.name,
            "size": self.size,
            "extension": self.extension,
            "is_dir": self.is_dir,
            "is_hidden": self.is_hidden,
            "content": self.content,
            "acl": self.acl or {},
        }


def read_text_preview(path: Path, max_bytes: int = 1024 * 256) -> str:
    extension = path.suffix.lower()
    if extension in BINARY_TEXT_EXTENSIONS:
        return extract_binary_text(path)

    if extension not in TEXT_EXTENSIONS:
        return ""

    try:
        with path.open("rb") as handle:
            data = handle.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    except OSError:
        return ""


def scan_directory(
    path: str | Path,
    allowed_extensions: Iterable[str] | None = None,
    extension_filter_enabled: bool = False,
    include_hidden: bool = True,
    include_system: bool = False,
    hidden_filter_enabled: bool = False,
    system_filter_enabled: bool = False,
) -> list[dict]:
    root_path = Path(path).expanduser().resolve()
    if not root_path.exists():
        raise FileNotFoundError(f"Scan path does not exist: {root_path}")

    extension_filter = normalize_extension_filter(allowed_extensions)
    records: list[FileRecord] = []
    for item in root_path.rglob("*"):
        if not item.is_file():
            continue
        extension = item.suffix.lower()
        if extension_filter_enabled and extension not in extension_filter:
            continue
        is_hidden = is_hidden_path(item)
        is_system = is_system_path(item)
        if hidden_filter_enabled or system_filter_enabled:
            if not ((hidden_filter_enabled and is_hidden) or (system_filter_enabled and is_system)):
                continue
        else:
            if is_hidden and not include_hidden:
                continue
            if is_system and not include_system:
                continue

        try:
            stat = item.stat()
        except OSError:
            continue

        records.append(
            FileRecord(
                source="local",
                path=str(item),
                name=item.name,
                size=stat.st_size,
                extension=extension,
                is_hidden=is_hidden,
                content=read_text_preview(item),
            )
        )

    return [record.to_dict() for record in records]


def is_hidden_path(path: Path) -> bool:
    if any(part.startswith(".") for part in path.parts):
        return True
    try:
        stat = path.stat()
    except OSError:
        return False
    if hasattr(stat, "st_file_attributes"):
        return bool(stat.st_file_attributes & 0x2)
    return False


def is_system_path(path: Path) -> bool:
    try:
        stat = path.stat()
    except OSError:
        return False
    if hasattr(stat, "st_file_attributes"):
        return bool(stat.st_file_attributes & 0x4)
    system_parts = {"$recycle.bin", "system volume information", "windows", "program files", "program files (x86)"}
    return any(part.lower() in system_parts for part in path.parts)


def normalize_records(records: Iterable[dict]) -> list[dict]:
    normalized: list[dict] = []
    for record in records:
        path = str(record.get("path", ""))
        name = record.get("name") or Path(path).name
        extension = record.get("extension") or Path(path).suffix.lower()
        normalized.append(
            {
                "source": record.get("source", "unknown"),
                "share": record.get("share"),
                "path": path,
                "name": name,
                "size": int(record.get("size") or 0),
                "extension": extension,
                "is_dir": bool(record.get("is_dir", False)),
                "is_hidden": bool(record.get("is_hidden", False)),
                "content": record.get("content", ""),
                "acl": record.get("acl") or {},
            }
        )
    return normalized
