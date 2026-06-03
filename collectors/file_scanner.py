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


def scan_directory(path: str | Path) -> list[dict]:
    root_path = Path(path).expanduser().resolve()
    if not root_path.exists():
        raise FileNotFoundError(f"Scan path does not exist: {root_path}")

    records: list[FileRecord] = []
    for item in root_path.rglob("*"):
        if not item.is_file():
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
                extension=item.suffix.lower(),
                is_hidden=is_hidden_path(item),
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
