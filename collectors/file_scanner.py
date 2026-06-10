from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from collectors.binary_extractor import BINARY_TEXT_EXTENSIONS, extract_binary_text


TEXT_EXTENSIONS = {
    ".adoc",
    ".aws",
    ".c",
    ".config",
    ".cpp",
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
    ".backup",
    ".dockerfile",
    ".h",
    ".hcl",
    ".hpp",
    ".ps1",
    ".psm1",
    ".psd1",
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
    ".htm",
    ".md",
    ".mobileconfig",
    ".netrc",
    ".npmrc",
    ".ovpn",
    ".pcf",
    ".pypirc",
    ".rdp",
    ".reg",
    ".rst",
    ".tf",
    ".tfstate",
    ".tfvars",
    ".yara",
}

METADATA_EXTENSIONS = {
    ".7z",
    ".accdb",
    ".avi",
    ".bin",
    ".bmp",
    ".bz2",
    ".cab",
    ".cer",
    ".crt",
    ".dat",
    ".db",
    ".dll",
    ".doc",
    ".dwg",
    ".dxf",
    ".eml",
    ".exe",
    ".gif",
    ".gpg",
    ".gz",
    ".heic",
    ".ics",
    ".iso",
    ".jar",
    ".jpeg",
    ".jpg",
    ".kdbx",
    ".key",
    ".keynote",
    ".lnk",
    ".mbox",
    ".mdb",
    ".mkv",
    ".mov",
    ".mp3",
    ".mp4",
    ".msg",
    ".msi",
    ".numbers",
    ".odp",
    ".ods",
    ".old",
    ".one",
    ".ost",
    ".ott",
    ".ots",
    ".p12",
    ".pages",
    ".pcf",
    ".pem",
    ".pfx",
    ".pgp",
    ".png",
    ".pst",
    ".ppt",
    ".pub",
    ".rar",
    ".rtf",
    ".sqlite",
    ".sqlite3",
    ".svg",
    ".swp",
    ".sys",
    ".tar",
    ".temp",
    ".tif",
    ".tiff",
    ".tgz",
    ".tmp",
    ".vhd",
    ".vhdx",
    ".vsd",
    ".vsdx",
    ".wav",
    ".xls",
    ".xlsb",
    ".xz",
    ".zip",
}

SCANNABLE_EXTENSIONS = TEXT_EXTENSIONS | BINARY_TEXT_EXTENSIONS | METADATA_EXTENSIONS


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


def detect_extension(path: str | Path) -> str:
    file_path = Path(path)
    suffix = file_path.suffix.lower()
    if suffix:
        return suffix
    name = file_path.name.lower()
    if name.startswith("."):
        return name
    if name == "dockerfile":
        return ".dockerfile"
    return ""


def matches_scan_filters(
    extension: str,
    is_hidden: bool,
    is_system: bool,
    extension_filter: set[str],
    extension_filter_enabled: bool,
    include_hidden: bool,
    include_system: bool,
    hidden_filter_enabled: bool,
    system_filter_enabled: bool,
) -> bool:
    active_filters = extension_filter_enabled or hidden_filter_enabled or system_filter_enabled
    if active_filters:
        matches_extension = extension_filter_enabled and extension in extension_filter
        matches_hidden = hidden_filter_enabled and is_hidden
        matches_system = system_filter_enabled and is_system
        if not (matches_extension or matches_hidden or matches_system):
            return False
        return True

    if is_hidden and not include_hidden:
        return False
    if is_system and not include_system:
        return False
    return True


@dataclass(slots=True)
class FileRecord:
    source: str
    path: str
    name: str
    size: int
    extension: str
    is_dir: bool = False
    is_hidden: bool = False
    is_system: bool = False
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
            "is_system": self.is_system,
            "content": self.content,
            "acl": self.acl or {},
        }


def read_text_preview(path: Path, max_bytes: int = 1024 * 256) -> str:
    extension = detect_extension(path)
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
    max_depth: int = 4,
) -> list[dict]:
    root_path = Path(path).expanduser().resolve()
    if not root_path.exists():
        raise FileNotFoundError(f"Scan path does not exist: {root_path}")

    extension_filter = normalize_extension_filter(allowed_extensions)
    records: list[FileRecord] = []

    def add_file(item: Path) -> None:
        extension = detect_extension(item)
        is_hidden = is_hidden_path(item)
        is_system = is_system_path(item)
        if not matches_scan_filters(
            extension,
            is_hidden,
            is_system,
            extension_filter,
            extension_filter_enabled,
            include_hidden,
            include_system,
            hidden_filter_enabled,
            system_filter_enabled,
        ):
            return

        try:
            stat = item.stat()
        except OSError:
            return

        records.append(
            FileRecord(
                source="local",
                path=str(item),
                name=item.name,
                size=stat.st_size,
                extension=extension,
                is_hidden=is_hidden,
                is_system=is_system,
                content=read_text_preview(item),
            )
        )

    def walk(folder: Path, depth: int) -> None:
        if depth > max_depth:
            return
        if is_skipped_scan_path(folder):
            return
        try:
            entries = list(folder.iterdir())
        except OSError:
            return

        for item in entries:
            try:
                is_dir = item.is_dir()
                is_file = item.is_file()
            except OSError:
                continue

            if is_dir:
                if is_skipped_scan_path(item):
                    continue
                is_hidden_dir = is_hidden_path(item)
                if is_hidden_dir and not (include_hidden or hidden_filter_enabled):
                    continue
                walk(item, depth + 1)
                continue

            if not is_file:
                continue

            add_file(item)

    if root_path.is_file():
        add_file(root_path)
    else:
        walk(root_path, 0)

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


def is_skipped_scan_path(path: Path) -> bool:
    normalized = str(path).replace("/", "\\").lower()
    if not normalized.endswith("\\"):
        normalized = f"{normalized}\\"
    skip_fragments = (
        "\\.codex\\",
        "\\.git\\",
        "\\.vscode\\",
        "\\node_modules\\",
        "\\appdata\\local\\temp\\",
        "\\appdata\\local\\microsoft\\edge\\",
        "\\appdata\\local\\google\\chrome\\",
        "\\appdata\\local\\packages\\",
        "\\appdata\\roaming\\microsoft\\windows\\recent\\",
    )
    return any(fragment in normalized for fragment in skip_fragments)


def is_system_path(path: Path) -> bool:
    system_parts = {"$recycle.bin", "system volume information", "windows", "program files", "program files (x86)"}
    try:
        stat = path.stat()
    except OSError:
        return False
    if hasattr(stat, "st_file_attributes"):
        return bool(stat.st_file_attributes & 0x4) or any(part.lower() in system_parts for part in path.parts)
    return any(part.lower() in system_parts for part in path.parts)


def normalize_records(records: Iterable[dict]) -> list[dict]:
    normalized: list[dict] = []
    for record in records:
        path = str(record.get("path", ""))
        name = record.get("name") or Path(path).name
        extension = record.get("extension") or detect_extension(path)
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
                "is_system": bool(record.get("is_system", False)),
                "content": record.get("content", ""),
                "acl": record.get("acl") or {},
            }
        )
    return normalized
