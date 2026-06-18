from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
import hashlib
import platform
import subprocess
import zipfile

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
ARCHIVE_EXTENSIONS = {".7z", ".bz2", ".cab", ".gz", ".jar", ".rar", ".tar", ".tgz", ".xz", ".zip"}
PROTECTED_CONTENT_EXTENSIONS = {".gpg", ".pgp", ".kdbx", ".p12", ".pfx"}
UNSUPPORTED_ARCHIVE_EXTENSIONS = ARCHIVE_EXTENSIONS - {".zip"}
CONTENT_EXTENSIONS = TEXT_EXTENSIONS | BINARY_TEXT_EXTENSIONS
MAX_ARCHIVE_ENTRY_BYTES = 25 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 200 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 2000
MAX_ARCHIVE_COMPRESSION_RATIO = 100


def scan_mode_for_extension(extension: str) -> str:
    if extension in TEXT_EXTENSIONS:
        return "plain_text"
    if extension in BINARY_TEXT_EXTENSIONS:
        return "document_text"
    if extension in PROTECTED_CONTENT_EXTENSIONS:
        return "protected_metadata"
    if extension in ARCHIVE_EXTENSIONS:
        return "archive_metadata"
    if extension in METADATA_EXTENSIONS:
        return "metadata_only"
    return "unknown"


def content_status_for_extension(extension: str, content: str, read_content: bool = True) -> str:
    if not read_content:
        return "not_requested"
    if extension in PROTECTED_CONTENT_EXTENSIONS:
        return "protected"
    if extension in UNSUPPORTED_ARCHIVE_EXTENSIONS:
        return "unsupported_archive"
    if extension in CONTENT_EXTENSIONS:
        return "scanned" if content else "empty_or_unreadable"
    return "metadata_only"


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
    content_status: str | None = None
    content_scannable: bool | None = None
    scan_error: str = ""
    protected: bool = False
    protection_type: str = ""
    owner: str = ""
    created_at: str = ""
    modified_at: str = ""
    attributes: str = ""
    sha256: str = ""

    def to_dict(self) -> dict:
        scan_mode = scan_mode_for_extension(self.extension)
        status = self.content_status or content_status_for_extension(self.extension, self.content)
        scannable = self.content_scannable if self.content_scannable is not None else self.extension in CONTENT_EXTENSIONS
        protected = self.protected or status in {"protected", "password_protected", "encrypted", "locked"}
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
            "scan_mode": scan_mode,
            "content_status": status,
            "content_scannable": scannable,
            "scan_error": self.scan_error,
            "protected": protected,
            "protection_type": self.protection_type,
            "owner": self.owner,
            "created_at": self.created_at,
            "modified_at": self.modified_at,
            "attributes": self.attributes,
            "sha256": self.sha256,
            "file_hash": self.sha256,
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


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(chunk_size), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return ""


def sha256_zip_entry(archive: zipfile.ZipFile, entry: zipfile.ZipInfo, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    try:
        with archive.open(entry) as handle:
            for chunk in iter(lambda: handle.read(chunk_size), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, RuntimeError, zipfile.BadZipFile):
        return ""


def file_owner(path: Path) -> str:
    try:
        owner = path.owner()
        if owner:
            return owner
    except (OSError, RuntimeError, NotImplementedError):
        pass

    if platform.system().lower() != "windows":
        return ""

    try:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$ErrorActionPreference='Stop'; (Get-Acl -LiteralPath $args[0]).Owner",
                str(path),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return ""

    if completed.returncode != 0:
        return ""
    return completed.stdout.strip().splitlines()[0] if completed.stdout.strip() else ""


def _is_safe_archive_entry(entry: zipfile.ZipInfo) -> bool:
    file_size = int(entry.file_size or 0)
    compressed = max(1, int(entry.compress_size or 1))
    if file_size > MAX_ARCHIVE_ENTRY_BYTES:
        return False
    if compressed > MAX_ARCHIVE_ENTRY_BYTES:
        return False
    if file_size / compressed > MAX_ARCHIVE_COMPRESSION_RATIO:
        return False
    return True


def scan_directory(
    path: str | Path,
    allowed_extensions: Iterable[str] | None = None,
    extension_filter_enabled: bool = False,
    include_hidden: bool = True,
    include_system: bool = False,
    hidden_filter_enabled: bool = False,
    system_filter_enabled: bool = False,
    max_depth: int = 4,
    inspect_archives: bool = False,
) -> list[dict]:
    root_path = Path(path).expanduser().resolve()
    if not root_path.exists():
        raise FileNotFoundError(f"Scan path does not exist: {root_path}")

    extension_filter = normalize_extension_filter(allowed_extensions)
    records: list[FileRecord] = []

    scan_archive_entries = inspect_archives

    def add_file(item: Path) -> None:
        try:
            if item.is_symlink() or not item.resolve().is_relative_to(root_path):
                return
        except OSError:
            return
        extension = detect_extension(item)
        is_hidden = is_hidden_path(item)
        is_system = is_system_path(item)
        attributes = file_attribute_label(item, is_hidden, is_system)
        zip_protection: dict[str, str | bool] = {}
        if scan_archive_entries and extension == ".zip":
            zip_protection = inspect_zip_protection(item)
            add_zip_entries(item, is_hidden, is_system)
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
        owner = file_owner(item)
        created_at = datetime.fromtimestamp(stat.st_ctime, timezone.utc).isoformat()
        modified_at = datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
        sha256 = sha256_file(item)

        protected_extension = extension in PROTECTED_CONTENT_EXTENSIONS
        unsupported_archive = inspect_archives and extension in UNSUPPORTED_ARCHIVE_EXTENSIONS
        content_status = None
        content_scannable = None
        scan_error = ""
        protection_type = ""
        protected = protected_extension or bool(zip_protection.get("protected"))
        if protected_extension:
            content_status = "protected"
            content_scannable = False
            protection_type = "encrypted_file"
            scan_error = "File extension indicates encrypted or protected content"
        elif zip_protection.get("status"):
            content_status = str(zip_protection.get("status"))
            content_scannable = False
            protection_type = str(zip_protection.get("protection_type") or "zip_password")
            scan_error = str(zip_protection.get("scan_error") or "ZIP archive contains encrypted entries")
        elif unsupported_archive:
            content_status = "unsupported_archive"
            content_scannable = False
            scan_error = "Archive type is metadata-only unless an extractor is configured"

        records.append(
            FileRecord(
                source="local",
                path=str(item),
                name=item.name,
                size=stat.st_size,
                extension=extension,
                is_hidden=is_hidden,
                is_system=is_system,
                content="" if protected or unsupported_archive else read_text_preview(item),
                content_status=content_status,
                content_scannable=content_scannable,
                scan_error=scan_error,
                protected=protected,
                protection_type=protection_type,
                owner=owner,
                created_at=created_at,
                modified_at=modified_at,
                attributes=attributes,
                sha256=sha256,
            )
        )

    def inspect_zip_protection(archive_path: Path) -> dict[str, str | bool]:
        try:
            with zipfile.ZipFile(archive_path) as archive:
                encrypted = any(bool(entry.flag_bits & 0x1) for entry in archive.infolist()[:MAX_ARCHIVE_ENTRIES])
                if encrypted:
                    return {
                        "protected": True,
                        "status": "password_protected",
                        "protection_type": "zip_password",
                        "scan_error": "ZIP archive has encrypted entries and needs a password",
                    }
                return {}
        except (OSError, RuntimeError, zipfile.BadZipFile):
            return {
                "protected": True,
                "status": "bad_archive",
                "protection_type": "unreadable_archive",
                "scan_error": "ZIP archive could not be opened or parsed",
            }


    def add_zip_entries(archive_path: Path, is_hidden: bool, is_system: bool, depth: int = 0) -> None:
        if depth > 2:
            return
        try:
            with zipfile.ZipFile(archive_path) as archive:
                entries = archive.infolist()[:MAX_ARCHIVE_ENTRIES]
                inflated_total = 0
                for entry in entries:
                    inflated_total += int(entry.file_size or 0)
                    if not _is_safe_archive_entry(entry) or inflated_total > MAX_ARCHIVE_TOTAL_BYTES:
                        continue
                    if entry.is_dir():
                        continue
                    entry_path = f"{archive_path}::{entry.filename}"
                    extension = detect_extension(entry.filename)
                    if entry.flag_bits & 0x1:
                        if matches_scan_filters(
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
                            records.append(
                                FileRecord(
                                    source="local",
                                    path=entry_path,
                                    name=Path(entry.filename).name,
                                    size=entry.file_size,
                                    extension=extension,
                                    is_hidden=is_hidden,
                                    is_system=is_system,
                                    content="",
                                    content_status="password_protected",
                                    content_scannable=False,
                                    scan_error="ZIP entry is encrypted and requires a password",
                                    protected=True,
                                    protection_type="zip_password",
                                    sha256="",
                                )
                            )
                        continue
                    if matches_scan_filters(
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
                        records.append(
                            FileRecord(
                                source="local",
                                path=entry_path,
                                name=Path(entry.filename).name,
                                size=entry.file_size,
                                extension=extension,
                                is_hidden=is_hidden,
                                is_system=is_system,
                                content=read_zip_entry_preview(archive, entry, extension),
                                sha256=sha256_zip_entry(archive, entry),
                            )
                        )
                    if extension == ".zip":
                        try:
                            from io import BytesIO

                            if not _is_safe_archive_entry(entry):
                                continue
                            nested = BytesIO(archive.read(entry))
                            with zipfile.ZipFile(nested) as nested_archive:
                                nested_total = 0
                                for nested_entry in nested_archive.infolist()[:MAX_ARCHIVE_ENTRIES]:
                                    nested_total += int(nested_entry.file_size or 0)
                                    if not _is_safe_archive_entry(nested_entry) or nested_total > MAX_ARCHIVE_TOTAL_BYTES:
                                        continue
                                    if nested_entry.is_dir():
                                        continue
                                    nested_path = f"{entry_path}::{nested_entry.filename}"
                                    nested_extension = detect_extension(nested_entry.filename)
                                    if nested_entry.flag_bits & 0x1:
                                        if matches_scan_filters(
                                            nested_extension,
                                            is_hidden,
                                            is_system,
                                            extension_filter,
                                            extension_filter_enabled,
                                            include_hidden,
                                            include_system,
                                            hidden_filter_enabled,
                                            system_filter_enabled,
                                        ):
                                            records.append(
                                                FileRecord(
                                                    source="local",
                                                    path=nested_path,
                                                    name=Path(nested_entry.filename).name,
                                                    size=nested_entry.file_size,
                                                    extension=nested_extension,
                                                    is_hidden=is_hidden,
                                                    is_system=is_system,
                                                    content="",
                                                    content_status="password_protected",
                                                    content_scannable=False,
                                                    scan_error="Nested ZIP entry is encrypted and requires a password",
                                                    protected=True,
                                                    protection_type="zip_password",
                                                    sha256="",
                                                )
                                            )
                                        continue
                                    if matches_scan_filters(
                                        nested_extension,
                                        is_hidden,
                                        is_system,
                                        extension_filter,
                                        extension_filter_enabled,
                                        include_hidden,
                                        include_system,
                                        hidden_filter_enabled,
                                        system_filter_enabled,
                                    ):
                                        records.append(
                                            FileRecord(
                                                source="local",
                                                path=nested_path,
                                                name=Path(nested_entry.filename).name,
                                                size=nested_entry.file_size,
                                                extension=nested_extension,
                                                is_hidden=is_hidden,
                                                is_system=is_system,
                                                content=read_zip_entry_preview(nested_archive, nested_entry, nested_extension),
                                                sha256=sha256_zip_entry(nested_archive, nested_entry),
                                            )
                                        )
                        except (OSError, RuntimeError, zipfile.BadZipFile):
                            continue
        except (OSError, RuntimeError, zipfile.BadZipFile):
            return

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
                if item.is_symlink() or not item.resolve().is_relative_to(root_path):
                    continue
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


def read_zip_entry_preview(archive: zipfile.ZipFile, entry: zipfile.ZipInfo, extension: str, max_bytes: int = 1024 * 256) -> str:
    if extension not in TEXT_EXTENSIONS or not _is_safe_archive_entry(entry):
        return ""
    try:
        with archive.open(entry) as handle:
            data = handle.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    except (OSError, RuntimeError, zipfile.BadZipFile):
        return ""


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


def file_attribute_label(path: Path, is_hidden: bool = False, is_system: bool = False) -> str:
    labels: list[str] = []
    try:
        stat = path.stat()
        attributes = getattr(stat, "st_file_attributes", 0)
    except OSError:
        attributes = 0
    if attributes & 0x20:
        labels.append("A")
    if attributes & 0x1:
        labels.append("R")
    if attributes & 0x2 or is_hidden:
        labels.append("H")
    if attributes & 0x4 or is_system:
        labels.append("S")
    return ", ".join(labels) or "Normal"


def normalize_records(records: Iterable[dict]) -> list[dict]:
    normalized: list[dict] = []
    for record in records:
        path = str(record.get("path", ""))
        name = record.get("name") or Path(path).name
        extension = record.get("extension") or detect_extension(path)
        sha256 = record.get("sha256") or record.get("file_hash") or ""
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
                "scan_mode": record.get("scan_mode") or scan_mode_for_extension(extension),
                "content_status": record.get("content_status")
                or content_status_for_extension(extension, str(record.get("content", ""))),
                "content_scannable": bool(record.get("content_scannable", extension in CONTENT_EXTENSIONS)),
                "scan_error": record.get("scan_error", ""),
                "protected": bool(record.get("protected", False)),
                "protection_type": record.get("protection_type", ""),
                "owner": record.get("owner", ""),
                "created_at": record.get("created_at", ""),
                "modified_at": record.get("modified_at", ""),
                "accessed_at": record.get("accessed_at", ""),
                "attributes": record.get("attributes", ""),
                "sha256": sha256,
                "file_hash": sha256,
            }
        )
    return normalized
