from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


TEXT_EXTENSIONS = {
    ".txt",
    ".log",
    ".csv",
    ".json",
    ".xml",
    ".yaml",
    ".yml",
    ".ini",
    ".cfg",
    ".conf",
    ".env",
    ".bak",
    ".sql",
    ".ps1",
    ".bat",
    ".cmd",
    ".py",
    ".js",
    ".ts",
    ".html",
    ".css",
    ".md",
}


@dataclass(slots=True)
class FileRecord:
    source: str
    path: str
    name: str
    size: int
    extension: str
    is_dir: bool = False
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
            "content": self.content,
            "acl": self.acl or {},
        }


def read_text_preview(path: Path, max_bytes: int = 1024 * 256) -> str:
    if path.suffix.lower() not in TEXT_EXTENSIONS:
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
                content=read_text_preview(item),
            )
        )

    return [record.to_dict() for record in records]


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
                "content": record.get("content", ""),
                "acl": record.get("acl") or {},
            }
        )
    return normalized
