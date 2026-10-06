from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable
import hashlib
import os
import platform
import re
import subprocess
import threading
import time
import zipfile

from collectors import content_policy
from collectors.binary_extractor import BINARY_TEXT_EXTENSIONS, extract_binary_bytes_detail, extract_binary_text
from collectors.ocr import extract_text_from_image, is_ocr_scannable, max_image_bytes
from collectors.text_decode import TextDecoder
from collectors import win_security
from discovery.incremental import apply_reuse_snapshot, reuse_snapshot_from_result


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
    # Credential material is text and has to be READ to be classified. Without
    # these a real private key was never opened: `.pem` resolved to
    # "metadata_only", produced no finding, and only ever showed up through its
    # extension score - a number with no evidence behind it.
    ".pem",
    ".key",
    ".crt",
    ".cer",
    ".pub",
    ".asc",
    ".ppk",
    ".kubeconfig",
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
    ".msix",
    ".msixbundle",
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
MAX_ARCHIVE_NESTING = 2
# M9 (roadmap 1.2): a REAL, enforced wall-clock budget for processing one
# archive (cooperative - checked between entries), replacing the previously
# advertised-but-cosmetic per-entry timeout. Bounds a slow/pathological multi-
# entry archive; a single hung entry parse is bounded separately (M8/extraction).
ARCHIVE_TOTAL_TIMEOUT_SECONDS = int(os.getenv("DSPM_ARCHIVE_TIMEOUT_SECONDS", "30"))
# The cap a collector that is configured once (SMB, WinRM) starts from; a local read asks
# content_policy.text_cap_bytes() each time (W2.2: 16 MiB, was 100 MiB).
DEFAULT_TEXT_SCAN_MAX_BYTES = int(os.getenv("DSPM_TEXT_SCAN_MAX_BYTES", str(content_policy.DEFAULT_TEXT_CAP_BYTES)))
TEXT_SCAN_CHUNK_BYTES = 1024 * 1024


def scan_mode_for_extension(extension: str) -> str:
    if extension in TEXT_EXTENSIONS:
        return "plain_text"
    if extension in BINARY_TEXT_EXTENSIONS:
        return "document_text"
    if extension in PROTECTED_CONTENT_EXTENSIONS:
        return "protected_metadata"
    if extension in ARCHIVE_EXTENSIONS:
        return "archive_metadata"
    if is_ocr_scannable(extension):
        return "image_ocr"
    if extension in METADATA_EXTENSIONS:
        return "metadata_only"
    return "unknown"


def content_status_for_extension(extension: str, content: str, read_content: bool = True) -> str:
    if not read_content:
        return "not_requested"
    if extension in PROTECTED_CONTENT_EXTENSIONS:
        return "protected"
    if extension in UNSUPPORTED_ARCHIVE_EXTENSIONS:
        return "protected_or_uninspectable_archive"
    if extension in CONTENT_EXTENSIONS or is_ocr_scannable(extension):
        return "scanned" if content else "empty_or_unreadable"
    return "metadata_only"


def archive_protection_metadata(extension: str) -> dict[str, str | bool]:
    if extension not in UNSUPPORTED_ARCHIVE_EXTENSIONS:
        return {}
    return {
        "protected": True,
        "content_status": "protected_or_uninspectable_archive",
        "content_scannable": False,
        "protection_type": "compressed_archive",
        "scan_error": "Compressed archive may be password-protected or requires a dedicated extractor",
    }


def _archive_safety_metadata(extension: str) -> dict:
    if extension not in ARCHIVE_EXTENSIONS:
        return {}
    return {
        "max_archive_nesting": MAX_ARCHIVE_NESTING,
        "max_archive_entry_bytes": MAX_ARCHIVE_ENTRY_BYTES,
        "max_archive_total_bytes": MAX_ARCHIVE_TOTAL_BYTES,
        "max_archive_entries": MAX_ARCHIVE_ENTRIES,
        "max_compression_ratio": MAX_ARCHIVE_COMPRESSION_RATIO,
        # M9: this budget is now actually enforced (cooperative, between entries),
        # unlike the old advertised-only per-entry timeout.
        "archive_timeout_seconds": ARCHIVE_TOTAL_TIMEOUT_SECONDS,
        "timeout_enforced": True,
        "zip_bomb_protection": True,
        "path_traversal_prevention": True,
        "symlink_prevention": True,
        "malware_quarantine_integration": "not_configured",
    }


# A valid file extension: a dot, an alphanumeric, then up to 40 of a small safe
# set. Shared by the frontend (identical regex) and the API validators.
EXTENSION_PATTERN = re.compile(r"\.[a-z0-9][a-z0-9._+-]{0,40}")
# Callers pass extensions as list items, but a single item may itself hold several
# tokens separated by commas / whitespace / semicolons / pipes (users type
# "pdf, docx" or "pdf docx", or paste a blob). Split on all of them.
_EXTENSION_SPLIT = re.compile(r"[,\s;|]+")
# Bound the result so a giant pasted blob can't create an unbounded filter set.
MAX_EXTENSION_FILTER = 256


def normalize_one_extension(token: str) -> str:
    """Normalize a single token to a canonical extension, or "" if it isn't one.

    Tolerant of the ways people type extensions: surrounding quotes, a leading
    glob (``*.pdf`` -> ``.pdf``), a missing dot (``pdf`` -> ``.pdf``), and case.
    Returns "" for anything that isn't a valid extension (dropped, never raised)."""
    token = str(token or "").strip().strip("'\"").strip().lower().lstrip("*")
    if not token:
        return ""
    if not token.startswith("."):
        token = f".{token}"
    return token if EXTENSION_PATTERN.fullmatch(token) else ""


def normalize_extension_filter(extensions: Iterable[str] | None) -> set[str]:
    """Canonical, tolerant extension-filter normalizer used by every scan type
    (local / SMB / WinRM) and the API validators, so they all agree. Splits
    multi-token items, drops invalid tokens instead of raising, and never lets a
    malformed policy fail a scan or leak a garbage filter that matches nothing."""
    normalized: set[str] = set()
    for item in extensions or []:
        for token in _EXTENSION_SPLIT.split(str(item or "")):
            extension = normalize_one_extension(token)
            if extension:
                normalized.add(extension)
                if len(normalized) >= MAX_EXTENSION_FILTER:
                    return normalized
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
    if extension_filter_enabled and extension not in extension_filter:
        return False
    if hidden_filter_enabled and not is_hidden:
        return False
    if not hidden_filter_enabled and is_hidden and not include_hidden:
        return False
    if system_filter_enabled and not is_system:
        return False
    if not system_filter_enabled and is_system and not include_system:
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
    content_hash: str = ""
    scan_completeness: str = "UNKNOWN"
    bytes_scanned: int = 0
    total_bytes: int = 0
    truncated: bool = False
    archive_scan_status: str = ""
    archive_safety: dict | None = None
    cache_reused: bool = False
    reused_preview: dict | None = None
    incremental_reused: bool = False
    baseline_result: dict | None = None
    reuse_key: str = ""
    # Why a content type was not read (W2.2: over a size cap) - not an error, and so not
    # in scan_error, which marks a record unfit for reuse.
    skip_reason: str = ""

    def to_dict(self) -> dict:
        scan_mode = scan_mode_for_extension(self.extension)
        status = self.content_status or content_status_for_extension(self.extension, self.content)
        scannable = self.content_scannable if self.content_scannable is not None else (self.extension in CONTENT_EXTENSIONS or is_ocr_scannable(self.extension))
        protected = self.protected or status in {"protected", "password_protected", "encrypted", "locked", "protected_or_uninspectable_archive"}
        record = {
            "cache_reused": self.cache_reused,
            "incremental_reused": self.incremental_reused,
            "reused_preview": self.reused_preview,
            "baseline_result": self.baseline_result,
            "reuse_key": self.reuse_key,
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
            "content_hash": self.content_hash,
            "scan_completeness": self.scan_completeness,
            "bytes_scanned": self.bytes_scanned,
            "total_bytes": self.total_bytes or self.size,
            "truncated": self.truncated,
            "archive_scan_status": self.archive_scan_status,
            "archive_safety": self.archive_safety or {},
            "skip_reason": self.skip_reason,
        }
        record["content_coverage"] = content_policy.coverage_state(record)
        return record


def read_text_preview(path: Path, max_bytes: int | None = None) -> str:
    extension = detect_extension(path)
    if extension in BINARY_TEXT_EXTENSIONS:
        return extract_binary_text(path)
    if is_ocr_scannable(extension):
        return extract_text_from_image(path)
    if extension not in TEXT_EXTENSIONS:
        return ""
    content, _sha256 = read_text_preview_and_sha256(path, max_bytes)
    return content


# Why the last read on this thread produced no text, kept for the record built from it.
# The read helper keeps its (text, hash) shape - the evidence reveal, the engine's re-read
# and the tests that stand in for it all call it so - and the walk builds the record from
# scan_completeness_for_path right after it, on the same thread.
_last_read = threading.local()

# What a document extractor's reason for "no text" means on the record.
_EXTRACTION_OUTCOMES = {
    "password_protected": {"content_status": "password_protected", "protection_type": "document_password",
                           "scan_error": "The document is encrypted and needs a password"},
    "no_text_layer": {"content_status": "no_text_layer"},
    "not_extracted": {"content_status": "not_extracted"},
}


def _note_read(path: Path, outcome: dict | None = None, truncated: bool = False) -> None:
    _last_read.outcome = (str(path), dict(outcome or {}), bool(truncated))


def _take_read_outcome(path: Path) -> tuple[dict, bool]:
    """(why the read got no text, whether the text it got is cut short)."""
    noted = getattr(_last_read, "outcome", None)
    _last_read.outcome = None
    return (noted[1], noted[2]) if noted and noted[0] == str(path) else ({}, False)


def _note_bytes(count: int) -> None:
    _last_read.bytes = int(getattr(_last_read, "bytes", 0) or 0) + int(count)


def take_read_bytes() -> int:
    """The bytes this thread read from files since it last asked (W2.2 measurements)."""
    count = int(getattr(_last_read, "bytes", 0) or 0)
    _last_read.bytes = 0
    return count


def _over_cap(cap_name: str, cap: int) -> dict:
    return {"content_status": "over_size_cap",
            "skip_reason": f"Larger than {cap_name} ({cap // (1024 * 1024)} MiB); its content was not read"}


def _unreadable(exc_type: str) -> dict:
    # The error's type only: its text can carry the path.
    return {"content_status": "unreadable", "scan_error": f"The file could not be read ({exc_type})"}


def read_text_preview_and_sha256(path: Path, max_bytes: int | None = None) -> tuple[str, str]:
    """(the text a scan inspects, the file's identity) - from one read (W2.2).

    A text file is read up to its cap: within it, the identity is the whole-file SHA-256
    of the same bytes; past it, ``head:<cap>:<SHA-256 of the bytes inspected>`` (or, under
    DSPM_HASH_POLICY=full, the rest is hashed too). A document or image within its cap is
    read once into memory - the hash and the text from the same bytes; over it, it is not
    read. Anything else is not read for content: its identity follows DSPM_HASH_POLICY.
    The evidence reveal calls this too, and gets the same identity from the same bytes.
    """
    extension = detect_extension(path)
    if extension in BINARY_TEXT_EXTENSIONS or is_ocr_scannable(extension):
        return _read_document(path, extension)
    _note_read(path)
    if extension not in TEXT_EXTENSIONS:
        return "", identity_without_content(path)
    cap = content_policy.text_cap_bytes() if max_bytes is None else max(0, int(max_bytes or 0))
    if cap <= 0:
        return "", identity_without_content(path)
    return _read_text(path, cap)


def _read_text(path: Path, cap: int) -> tuple[str, str]:
    full = content_policy.hash_policy() == "full"
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            # One decoder across the chunks: it knows the file's encoding (a UTF-16
            # export is not UTF-8) and carries a character split by a chunk boundary.
            decoder = TextDecoder()
            chunks: list[str] = []
            remaining = cap
            while remaining > 0:
                chunk = handle.read(min(TEXT_SCAN_CHUNK_BYTES, remaining))
                if not chunk:
                    break
                _note_bytes(len(chunk))
                digest.update(chunk)
                chunks.append(decoder.decode(chunk))
                remaining -= len(chunk)
            beyond = handle.read(1) if remaining == 0 else b""
            if beyond:
                _note_bytes(1)
            if beyond and full:
                # The whole-file digest asked for: hash the rest, keep none of it.
                digest.update(beyond)
                for chunk in iter(lambda: handle.read(TEXT_SCAN_CHUNK_BYTES), b""):
                    _note_bytes(len(chunk))
                    digest.update(chunk)
            chunks.append(decoder.decode(b"", final=True))
        text = "".join(chunks)
        if beyond and not full:
            return text, content_policy.head_identity(cap, digest.hexdigest())
        return text, digest.hexdigest()
    except OSError as exc:
        # Said on the record: a file that could not be opened (a sharing violation, read
        # denied) is not an empty file, and is read again next time rather than reused.
        _note_read(path, _unreadable(type(exc).__name__))
        return "", ""


def _read_document(path: Path, extension: str) -> tuple[str, str]:
    """A document or an image: within its cap, read once - the whole-file SHA-256 and the
    text from the same bytes (it used to be extracted, then read again to hash, E4)."""
    image = extension not in BINARY_TEXT_EXTENSIONS
    cap = max_image_bytes() if image else content_policy.document_cap_bytes()
    try:
        size = path.stat().st_size
        if size > cap:
            _note_read(path, _over_cap("DSPM_OCR_MAX_FILE_BYTES" if image else "DSPM_DOCUMENT_SCAN_MAX_BYTES", cap))
            return "", identity_without_content(path)
        data = path.read_bytes()
    except OSError as exc:
        # A document that could not be opened is a failed read, not one with no text.
        _note_read(path, _unreadable(type(exc).__name__))
        return "", ""
    _note_bytes(len(data))
    sha256 = hashlib.sha256(data).hexdigest()
    if image:
        text, reason, truncated = extract_text_from_image(path, digest=sha256), "", False
    else:
        text, reason, truncated = extract_binary_bytes_detail(data, extension)
    _note_read(path, _EXTRACTION_OUTCOMES.get(reason), truncated=truncated)
    return text, sha256


def identity_without_content(path: Path) -> str:
    """The identity of a file whose content is not read whole, by DSPM_HASH_POLICY: meta
    (size, mtime, file id; nothing read), sampled (first and last MiB), full (every byte)."""
    policy = content_policy.hash_policy()
    try:
        stat = path.stat()
    except OSError:
        return ""
    if policy == "full" or (policy == "sampled" and not content_policy.needs_sample(stat.st_size)):
        # A file of at most 2 MiB is hashed whole under "sampled": that is all a sample reads.
        return _sha256_and_error(path)[0]
    if policy == "sampled":
        sample = content_policy.SAMPLE_BYTES
        try:
            with path.open("rb") as handle:
                head = handle.read(sample)
                handle.seek(-sample, os.SEEK_END)
                tail = handle.read(sample)
        except OSError:
            return ""
        _note_bytes(len(head) + len(tail))
        return content_policy.sampled_identity(stat.st_size, head, tail)
    file_id = f"{stat.st_dev}:{stat.st_ino}" if getattr(stat, "st_ino", 0) else ""
    return content_policy.meta_identity(stat.st_size, stat.st_mtime_ns, file_id)


def scan_completeness_for_path(path: Path, content: str, protected: bool = False, max_bytes: int | None = None) -> dict:
    """How much of the file the scan read - and, when the read that produced ``content``
    got no text out of it, why: ``content_status`` (with ``scan_error``,
    ``protection_type`` or ``skip_reason`` when there is one to say) for the record."""
    if max_bytes is None:
        max_bytes = content_policy.text_cap_bytes()
    outcome, cut_short = _take_read_outcome(path)
    try:
        total_bytes = path.stat().st_size
    except OSError:
        total_bytes = 0
    if outcome and not content:
        return {"scan_completeness": "NONE", "bytes_scanned": 0, "total_bytes": total_bytes, "truncated": False,
                **outcome}
    if protected:
        return {"scan_completeness": "NONE", "bytes_scanned": 0, "total_bytes": total_bytes, "truncated": bool(total_bytes)}
    extension = detect_extension(path)
    if extension in TEXT_EXTENSIONS:
        bytes_scanned = min(total_bytes, max(0, int(max_bytes or 0)))
        truncated = total_bytes > max(0, int(max_bytes or 0))
    elif extension in BINARY_TEXT_EXTENSIONS or is_ocr_scannable(extension):
        bytes_scanned = total_bytes if content else 0
        # The extractor says when it stopped with document left or skipped a part; the
        # character budget alone missed a part dropped as too large (E5).
        truncated = bool(content) and (cut_short or len(content) >= 120_000)
    else:
        bytes_scanned = 0
        truncated = False
    return {
        "scan_completeness": "PARTIAL" if truncated else "FULL" if bytes_scanned or total_bytes == 0 else "NONE",
        "bytes_scanned": bytes_scanned,
        "total_bytes": total_bytes,
        "truncated": truncated,
    }


def content_hash_value(content: str) -> str:
    return hashlib.sha256(str(content or "").encode("utf-8", errors="replace")).hexdigest() if content else ""


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    return _sha256_and_error(path, chunk_size)[0]


def _sha256_and_error(path: Path, chunk_size: int = 1024 * 1024) -> tuple[str, str]:
    """(digest, "") - or ("", the type of the error) when the file could not be read."""
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(chunk_size), b""):
                _note_bytes(len(chunk))
                digest.update(chunk)
        return digest.hexdigest(), ""
    except OSError as exc:
        return "", type(exc).__name__


def sha256_zip_entry(archive: zipfile.ZipFile, entry: zipfile.ZipInfo, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    try:
        with archive.open(entry) as handle:
            for chunk in iter(lambda: handle.read(chunk_size), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, RuntimeError, zipfile.BadZipFile):
        return ""


def local_acl(path: Path) -> dict:
    """D7: the file's owner and access-control entries, read in-process on Windows - {}
    elsewhere, when the descriptor cannot be read, or with DSPM_LOCAL_ACL=0. A local scan
    used to read only the owner, so no local file was ever assessed for broad access."""
    if os.getenv("DSPM_LOCAL_ACL", "1").strip() == "0":
        return {}
    acl = win_security.security_for_path(str(path))
    return acl if (acl.get("owner") or acl.get("entries")) else {}


def file_owner(path: Path) -> str:
    try:
        owner = path.owner()
        if owner:
            return owner
    except (OSError, RuntimeError, NotImplementedError):
        pass

    if platform.system().lower() != "windows":
        return ""

    # PERF: read the owner from the security descriptor in-process. Spawning a
    # PowerShell per file cost ~490 ms and was 91% of total scan time; this is
    # ~0.8 ms for a byte-identical answer. The subprocess below remains as the
    # fallback for hosts where the Win32 path is unavailable.
    owner = win_security.owner_for_path(str(path))
    if owner:
        return owner

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
    name = str(entry.filename or "")
    try:
        parts = Path(name).parts
    except Exception:
        return False
    if Path(name).is_absolute() or ".." in parts:
        return False
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
    diagnostics: dict | None = None,
    reuse_probe: Callable[[str, int, str], dict | None] | None = None,
    reuse_key_builder: Callable[[str], str] | None = None,
    progress_callback: Callable[[int, int, int], None] | None = None,
    record_callback: Callable[[dict], None] | None = None,
    excluded_paths: Iterable[str | Path] | None = None,
    include_names: Iterable[str] | None = None,
    containment_root: str | Path | None = None,
    resolve_root: bool = True,
    cancel_check: Callable[[], bool] | None = None,
    read_content: bool = True,
    scope: dict | None = None,
) -> list[dict]:
    """Walk a folder - or read one file - into file records.

    ``scope`` is the scan's advanced scope (collectors.scan_scope, canonical form). A
    folder out of scope is not listed; a file out of scope by its path or extension is
    left before any stat, and one out of scope by its size or modification time after
    one stat - never opened, hashed, read for ACLs or recorded. What it left out, and
    why, is ``diagnostics["scope"]``.

    ``read_content=False`` is the inventory level (W2.6): names, sizes, owners and
    access, no byte of content - each file named by its metadata, and said to be not
    read (SKIPPED_POLICY).

    A partitioned scan reads one run of a folder's entries at a time (B2.2b), and has
    to get exactly the records, in exactly the order, a whole walk would:

    - ``include_names`` walks only those entries of ``path``, in the order given - the
      order the folder listed them when the scan was planned - and descends into the
      folders among them as a whole walk would. The folder is not listed again, so a
      huge flat folder read in many runs is not listed once per run.
    - ``containment_root`` is the root of the whole scan. An entry is kept only if its
      real path lies under it - the same test a whole walk applies - rather than under
      this run's own folder, which a junction to a sibling folder would fail.
    - ``resolve_root=False`` keeps ``path`` as the walk spelled it, so a run inside a
      junction reports the paths a whole walk reports.

    ``cancel_check`` is asked before each entry. Once it says stop, the walk returns
    what it has and sets ``diagnostics["walk_cancelled"]``: the caller has to treat
    such a walk as incomplete, or everything it never reached reads as deleted.
    """
    root_path = Path(path).expanduser()
    if resolve_root:
        root_path = root_path.resolve()
    named_entries = list(include_names) if include_names is not None else None
    if not root_path.exists():
        raise FileNotFoundError(f"Scan path does not exist: {root_path}")

    containment = Path(containment_root).expanduser().resolve() if containment_root is not None else root_path
    extension_filter = normalize_extension_filter(allowed_extensions)
    from collectors.scan_scope import ScopeTally, rules_for

    scope_rules = rules_for(scope)
    scope_tally = ScopeTally() if scope_rules.active else None
    excluded_roots: list[Path] = []
    for excluded in excluded_paths or []:
        try:
            excluded_roots.append(Path(excluded).expanduser().resolve())
        except OSError:
            continue
    records: list[FileRecord | dict] = []
    progress_counters = {"visited": 0, "matched": 0, "reused": 0}
    # PERF: resolving every entry cost one _getfinalpathname syscall per file
    # (5,696 calls / 0.48 s on the sample tree). Directories are resolved once
    # and reused. This is NOT a weakening of the symlink-escape check: callers
    # test `item.is_symlink()` first, and for a non-symlink entry the real path
    # is exactly realpath(parent) / name.
    _resolved_dirs: dict[Path, Path] = {}

    def _resolved_entry(item: Path) -> Path:
        parent = item.parent
        resolved_parent = _resolved_dirs.get(parent)
        if resolved_parent is None:
            resolved_parent = parent.resolve()
            _resolved_dirs[parent] = resolved_parent
        return resolved_parent / item.name

    def _append_record(record: FileRecord | dict) -> None:
        records.append(record)
        if record_callback is not None:
            record_callback(record.to_dict() if isinstance(record, FileRecord) else dict(record))

    def _excluded(item: Path) -> bool:
        if not excluded_roots:
            return False
        try:
            resolved = _resolved_entry(item)
        except OSError:
            return False
        return any(resolved == excluded or excluded in resolved.parents for excluded in excluded_roots)

    def _scope_path(item: Path) -> str:
        """An entry's path in the scope's form: relative to the scan's root, or absolute."""
        resolved = _resolved_entry(item)
        if scope_rules.absolute:
            return scope_rules.path_of(str(resolved))
        try:
            return scope_rules.path_of(str(resolved.relative_to(containment)))
        except ValueError:
            return scope_rules.path_of(item.name)

    def _emit_progress(force: bool = False) -> None:
        if progress_callback is None:
            return
        # Throttle to keep the callback cheap during large walks.
        if not force and progress_counters["visited"] % 25 != 0:
            return
        try:
            progress_callback(
                progress_counters["visited"],
                progress_counters["matched"],
                progress_counters["reused"],
            )
        except Exception:
            return

    scan_archive_entries = inspect_archives
    if diagnostics is not None:
        diagnostics.setdefault("resolved_roots", []).append(str(root_path))
        diagnostics.setdefault("visited_files", 0)
        diagnostics.setdefault("matched_files", 0)
        diagnostics.setdefault("reused_files", 0)
        diagnostics.setdefault("skipped_dirs", 0)
        diagnostics.setdefault("unreadable_dirs", [])
        diagnostics.setdefault("extension_histogram", {})
        diagnostics.setdefault("archive_files", 0)
        diagnostics.setdefault("archive_entries", 0)
        diagnostics.setdefault("archive_entries_skipped", 0)
        diagnostics.setdefault("archive_errors", [])

    def add_file(item: Path) -> None:
        if _excluded(item):
            return
        try:
            if item.is_symlink() or not _resolved_entry(item).is_relative_to(containment):
                return
        except OSError:
            return
        extension = detect_extension(item)
        scoped_stat = None
        if scope_tally is not None:
            # Advanced scope, before anything is read: the name rules need no stat, the
            # size and date rules one - which the record then reuses.
            try:
                reason = scope_rules.file_name_reason(_scope_path(item), extension)
            except OSError:
                return
            if not reason and scope_rules.needs_metadata:
                try:
                    scoped_stat = item.stat()
                except OSError:
                    return
                reason = scope_rules.file_meta_reason(scoped_stat.st_size, scoped_stat.st_mtime)
            if reason:
                progress_counters["visited"] += 1
                _emit_progress()
                if diagnostics is not None:
                    diagnostics["visited_files"] = int(diagnostics.get("visited_files") or 0) + 1
                scope_tally.file(reason)
                return
        progress_counters["visited"] += 1
        _emit_progress()
        if diagnostics is not None:
            diagnostics["visited_files"] = int(diagnostics.get("visited_files") or 0) + 1
            extension_key = extension or "no extension"
            histogram = diagnostics.setdefault("extension_histogram", {})
            histogram[extension_key] = int(histogram.get(extension_key) or 0) + 1
        # The file-type policy needs the name alone: a file it leaves out costs no
        # syscall - unless it is an archive this scan opens, whose entries are judged
        # one by one.
        if extension_filter_enabled and extension not in extension_filter \
                and not (scan_archive_entries and extension == ".zip"):
            return
        # One stat answers hidden, system, the attribute label and the record's size and
        # times (the scope's own stat, when it took one).
        try:
            stat = scoped_stat or item.stat()
        except OSError:
            return
        file_attributes = int(getattr(stat, "st_file_attributes", 0) or 0)
        is_hidden = hidden_by(item, file_attributes)
        is_system = system_by(item, file_attributes)
        attributes = attribute_label(file_attributes, is_hidden, is_system)
        zip_protection: dict[str, str | bool] = {}
        include_top = matches_scan_filters(
            extension,
            is_hidden,
            is_system,
            extension_filter,
            extension_filter_enabled,
            include_hidden,
            include_system,
            hidden_filter_enabled,
            system_filter_enabled,
        )
        if not include_top and scan_archive_entries and extension == ".zip":
            add_zip_entries(item, is_hidden, is_system)
            return
        if not include_top:
            return

        created_at = datetime.fromtimestamp(stat.st_ctime, timezone.utc).isoformat()
        modified_at = datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
        protected_extension = extension in PROTECTED_CONTENT_EXTENSIONS
        object_key = reuse_key_builder(str(item)) if reuse_key_builder is not None else str(item)

        # Metadata-first reuse: when identity + size + mtime + policy version
        # match, restore the analyzed snapshot and skip owner, content, hash and
        # detector work. Archive-entry inspection is restored as an outer-file
        # bundle; a missing/incomplete bundle fails closed to a normal read.
        if (
            reuse_probe is not None
        ):
            snapshot = None
            try:
                snapshot = reuse_probe(object_key, int(stat.st_size), modified_at)
            except Exception:
                snapshot = None
            if scan_archive_entries and extension == ".zip" and not bool((snapshot or {}).get("archive_bundle_complete")):
                snapshot = None
            if isinstance(snapshot, dict):
                _append_record(
                    FileRecord(
                        source="local",
                        path=str(item),
                        name=item.name,
                        size=stat.st_size,
                        extension=extension,
                        is_hidden=is_hidden,
                        is_system=is_system,
                        content="",
                        acl=snapshot.get("acl") or {},
                        content_status=str(snapshot.get("content_status") or "reused_from_cache"),
                        content_scannable=bool(snapshot.get("content_scannable", False)),
                        scan_error=str(snapshot.get("scan_error") or ""),
                        protected=bool(snapshot.get("protected", False)),
                        protection_type=str(snapshot.get("protection_type") or ""),
                        owner=str(snapshot.get("owner") or ""),
                        created_at=created_at,
                        modified_at=modified_at,
                        attributes=attributes,
                        sha256=str(snapshot.get("sha256") or ""),
                        content_hash=str(snapshot.get("content_hash") or ""),
                        scan_completeness=str(snapshot.get("scan_completeness") or "UNKNOWN"),
                        bytes_scanned=int(snapshot.get("bytes_scanned") or 0),
                        total_bytes=int(snapshot.get("total_bytes") or stat.st_size),
                        truncated=bool(snapshot.get("truncated", False)),
                        archive_scan_status="not_archive",
                        archive_safety={},
                        cache_reused=True,
                        incremental_reused=bool(snapshot.get("baseline_result")),
                        reused_preview=snapshot.get("preview") if isinstance(snapshot.get("preview"), dict) else None,
                        baseline_result=snapshot.get("baseline_result") if isinstance(snapshot.get("baseline_result"), dict) else None,
                        reuse_key=object_key,
                    )
                )
                archive_records = snapshot.get("archive_records") if isinstance(snapshot.get("archive_records"), list) else []
                for prior in archive_records:
                    if not isinstance(prior, dict):
                        continue
                    child_key = str(prior.get("reuse_key") or prior.get("path") or "")
                    _append_record(
                        apply_reuse_snapshot(prior, reuse_snapshot_from_result(prior), child_key)
                    )
                if diagnostics is not None:
                    diagnostics["matched_files"] = int(diagnostics.get("matched_files") or 0) + 1 + len(archive_records)
                    diagnostics["reused_files"] = int(diagnostics.get("reused_files") or 0) + 1 + len(archive_records)
                    diagnostics["archive_entries"] = int(diagnostics.get("archive_entries") or 0) + len(archive_records)
                progress_counters["matched"] += 1 + len(archive_records)
                progress_counters["reused"] += 1 + len(archive_records)
                _emit_progress()
                return

        if scan_archive_entries and extension == ".zip":
            add_zip_entries(item, is_hidden, is_system)
        if extension == ".zip":
            zip_protection = inspect_zip_protection(item)

        acl = local_acl(item)
        owner = str(acl.get("owner") or "") or file_owner(item)
        archive_metadata = archive_protection_metadata(extension)
        content_status = None
        content_scannable = None
        scan_error = ""
        protection_type = ""
        protected = protected_extension or bool(zip_protection.get("protected")) or bool(archive_metadata.get("protected"))
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
        elif archive_metadata:
            content_status = str(archive_metadata.get("content_status") or "")
            content_scannable = False
            protection_type = str(archive_metadata.get("protection_type") or "")
            scan_error = str(archive_metadata.get("scan_error") or "")

        if protected or not read_content:
            content = ""
            sha256 = identity_without_content(item)
            if not protected and (extension in CONTENT_EXTENSIONS or is_ocr_scannable(extension)):
                content_status = "not_requested"
        else:
            content, sha256 = read_text_preview_and_sha256(item)
        if diagnostics is not None:
            diagnostics["content_bytes_read"] = int(diagnostics.get("content_bytes_read") or 0) + take_read_bytes()
        scan_meta = scan_completeness_for_path(item, content, protected)
        if not read_content and not protected:
            # Nothing was read: a text file must not count its first bytes as scanned.
            scan_meta = {"scan_completeness": "FULL" if stat.st_size == 0 else "NONE", "bytes_scanned": 0,
                         "total_bytes": stat.st_size, "truncated": False}
        _append_record(
            FileRecord(
                source="local",
                path=str(item),
                name=item.name,
                size=stat.st_size,
                extension=extension,
                is_hidden=is_hidden,
                is_system=is_system,
                content=content,
                # A read that got no text says why (unreadable, no text layer, sealed).
                content_status=content_status or scan_meta.get("content_status"),
                content_scannable=content_scannable,
                scan_error=scan_error or str(scan_meta.get("scan_error") or ""),
                protected=protected,
                protection_type=protection_type or str(scan_meta.get("protection_type") or ""),
                skip_reason=str(scan_meta.get("skip_reason") or ""),
                owner=owner,
                acl=acl,
                created_at=created_at,
                modified_at=modified_at,
                attributes=attributes,
                sha256=sha256,
                content_hash=content_hash_value(content),
                reuse_key=object_key,
                scan_completeness=str(scan_meta.get("scan_completeness") or "UNKNOWN"),
                bytes_scanned=int(scan_meta.get("bytes_scanned") or 0),
                total_bytes=int(scan_meta.get("total_bytes") or stat.st_size),
                truncated=bool(scan_meta.get("truncated")),
                archive_scan_status="inspected" if extension == ".zip" and scan_archive_entries else "metadata_only" if extension in ARCHIVE_EXTENSIONS else "not_archive",
                archive_safety=_archive_safety_metadata(extension),
            )
        )
        if diagnostics is not None:
            diagnostics["matched_files"] = int(diagnostics.get("matched_files") or 0) + 1
        progress_counters["matched"] += 1
        _emit_progress()

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
        if depth > MAX_ARCHIVE_NESTING:
            return
        try:
            with zipfile.ZipFile(archive_path) as archive:
                if diagnostics is not None:
                    diagnostics["archive_files"] = int(diagnostics.get("archive_files") or 0) + 1
                entries = archive.infolist()[:MAX_ARCHIVE_ENTRIES]
                if diagnostics is not None and len(archive.infolist()) > MAX_ARCHIVE_ENTRIES:
                    diagnostics["archive_entries_skipped"] = int(diagnostics.get("archive_entries_skipped") or 0) + (len(archive.infolist()) - MAX_ARCHIVE_ENTRIES)
                inflated_total = 0
                archive_deadline = time.monotonic() + ARCHIVE_TOTAL_TIMEOUT_SECONDS
                for entry in entries:
                    # M9: enforced total budget - stop processing further entries
                    # once this archive has consumed its wall-clock allowance.
                    if time.monotonic() > archive_deadline:
                        if diagnostics is not None:
                            diagnostics["archive_timed_out"] = True
                        break
                    inflated_total += int(entry.file_size or 0)
                    if not _is_safe_archive_entry(entry) or inflated_total > MAX_ARCHIVE_TOTAL_BYTES:
                        if diagnostics is not None:
                            diagnostics["archive_entries_skipped"] = int(diagnostics.get("archive_entries_skipped") or 0) + 1
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
                            _append_record(
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
                        content, sha256 = read_zip_entry_preview_and_sha256(archive, entry, extension)
                        _append_record(
                            FileRecord(
                                source="local",
                                path=entry_path,
                                name=Path(entry.filename).name,
                                size=entry.file_size,
                                extension=extension,
                                is_hidden=is_hidden,
                                is_system=is_system,
                                content=content,
                                sha256=sha256,
                                content_hash=content_hash_value(content),
                                **_zip_entry_coverage(entry, extension),
                                archive_scan_status="entry_scanned",
                                archive_safety=_archive_safety_metadata(".zip"),
                            )
                        )
                        if diagnostics is not None:
                            diagnostics["archive_entries"] = int(diagnostics.get("archive_entries") or 0) + 1
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
                                            _append_record(
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
                                        nested_content, nested_sha256 = read_zip_entry_preview_and_sha256(nested_archive, nested_entry, nested_extension)
                                        _append_record(
                                            FileRecord(
                                                source="local",
                                                path=nested_path,
                                                name=Path(nested_entry.filename).name,
                                                size=nested_entry.file_size,
                                                extension=nested_extension,
                                                is_hidden=is_hidden,
                                                is_system=is_system,
                                                content=nested_content,
                                                sha256=nested_sha256,
                                                content_hash=content_hash_value(nested_content),
                                                **_zip_entry_coverage(nested_entry, nested_extension),
                                                archive_scan_status="entry_scanned",
                                                archive_safety=_archive_safety_metadata(".zip"),
                                            )
                                        )
                        except (OSError, RuntimeError, zipfile.BadZipFile):
                            continue
        except (OSError, RuntimeError, zipfile.BadZipFile):
            return

    def walk(folder: Path, depth: int) -> None:
        if depth > max_depth:
            return
        if _excluded(folder):
            if diagnostics is not None:
                diagnostics["skipped_dirs"] = int(diagnostics.get("skipped_dirs") or 0) + 1
            return
        if is_skipped_scan_path(folder):
            if diagnostics is not None:
                diagnostics["skipped_dirs"] = int(diagnostics.get("skipped_dirs") or 0) + 1
            return
        try:
            if depth == 0 and named_entries is not None:
                entries = [folder / name for name in named_entries]
            else:
                entries = list(folder.iterdir())
        except OSError as exc:
            if diagnostics is not None:
                unreadable = diagnostics.setdefault("unreadable_dirs", [])
                if len(unreadable) < 20:
                    unreadable.append(f"{folder}: {exc}")
            return

        for item in entries:
            if cancel_check is not None and cancel_check():
                # A cancelled or over-budget scan used to keep walking - reading,
                # hashing and owner-checking every remaining file - for a report that
                # would only be thrown away or truncated.
                if diagnostics is not None:
                    diagnostics["walk_cancelled"] = True
                return
            try:
                if item.is_symlink() or not _resolved_entry(item).is_relative_to(containment):
                    continue
                is_dir = item.is_dir()
                is_file = item.is_file()
            except OSError:
                continue

            if is_dir:
                if is_skipped_scan_path(item):
                    if diagnostics is not None:
                        diagnostics["skipped_dirs"] = int(diagnostics.get("skipped_dirs") or 0) + 1
                    continue
                is_hidden_dir = is_hidden_path(item)
                if is_hidden_dir and not (include_hidden or hidden_filter_enabled):
                    if diagnostics is not None:
                        diagnostics["skipped_dirs"] = int(diagnostics.get("skipped_dirs") or 0) + 1
                    continue
                if scope_tally is not None:
                    reason = scope_rules.folder_reason(_scope_path(item))
                    if reason:
                        # Out of scope: not listed, so nothing under it is counted or read.
                        scope_tally.folder(reason)
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

    if diagnostics is not None and scope_tally is not None:
        block = scope_tally.to_dict(scope if isinstance(scope, dict) else None)
        if isinstance(diagnostics.get("scope"), dict):
            # One diagnostics dict over several roots (a local endpoint's folders): added up.
            from collectors.scan_scope import merge_diagnostics

            block = merge_diagnostics([diagnostics["scope"], block])
        diagnostics["scope"] = block
    _emit_progress(force=True)
    return [record.to_dict() if isinstance(record, FileRecord) else record for record in records]


def _zip_entry_coverage(entry: zipfile.ZipInfo, extension: str) -> dict:
    """What a record says it read of an archive entry. Only a text entry is read for
    content; any other entry used to be FULL with every byte "scanned" (E5)."""
    size = int(entry.file_size or 0)
    if extension not in TEXT_EXTENSIONS or not _is_safe_archive_entry(entry):
        return {"scan_completeness": "FULL" if size == 0 else "NONE", "bytes_scanned": 0,
                "total_bytes": size, "truncated": False}
    return {"scan_completeness": "PARTIAL" if size > MAX_ARCHIVE_ENTRY_BYTES else "FULL",
            "bytes_scanned": min(size, MAX_ARCHIVE_ENTRY_BYTES), "total_bytes": size,
            "truncated": size > MAX_ARCHIVE_ENTRY_BYTES}


def read_zip_entry_preview(archive: zipfile.ZipFile, entry: zipfile.ZipInfo, extension: str, max_bytes: int = MAX_ARCHIVE_ENTRY_BYTES) -> str:
    content, _sha256 = read_zip_entry_preview_and_sha256(archive, entry, extension, max_bytes)
    return content


def read_zip_entry_preview_and_sha256(archive: zipfile.ZipFile, entry: zipfile.ZipInfo, extension: str, max_bytes: int = MAX_ARCHIVE_ENTRY_BYTES) -> tuple[str, str]:
    if extension not in TEXT_EXTENSIONS or not _is_safe_archive_entry(entry):
        return "", sha256_zip_entry(archive, entry)
    digest = hashlib.sha256()
    try:
        with archive.open(entry) as handle:
            remaining = max(0, int(max_bytes or 0))
            decoder = TextDecoder()  # as read_text_preview_and_sha256: the entry's encoding, across chunks
            chunks: list[str] = []
            while True:
                chunk = handle.read(TEXT_SCAN_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
                if remaining > 0:
                    preview_chunk = chunk[:remaining]
                    chunks.append(decoder.decode(preview_chunk))
                    remaining -= len(preview_chunk)
            chunks.append(decoder.decode(b"", final=True))
        return "".join(chunks), digest.hexdigest()
    except (OSError, RuntimeError, zipfile.BadZipFile):
        return "", ""


def hidden_by(path: Path, file_attributes: int) -> bool:
    """Hidden: under a dotted name, or carrying the hidden attribute."""
    return any(part.startswith(".") for part in path.parts) or bool(file_attributes & 0x2)


def is_hidden_path(path: Path) -> bool:
    if any(part.startswith(".") for part in path.parts):
        return True
    try:
        stat = path.stat()
    except OSError:
        return False
    return hidden_by(path, int(getattr(stat, "st_file_attributes", 0) or 0))


def is_skipped_scan_path(path: Path) -> bool:
    normalized = str(path).replace("/", "\\").lower()
    if not normalized.endswith("\\"):
        normalized = f"{normalized}\\"
    skip_fragments = (
        "\\.codex\\",
        "\\.git\\",
        "\\.vscode\\",
        "\\node_modules\\",
        "\\$recycle.bin\\",
        "\\system volume information\\",
        "\\$winreagent\\",
        "\\recovery\\",
        "\\config.msi\\",
        "\\perflogs\\",
        "\\msocache\\",
        "\\windows\\",
        "\\program files\\",
        "\\program files (x86)\\",
        "\\programdata\\",
        "\\appdata\\",
        "\\appdata\\local\\temp\\",
        "\\appdata\\local\\microsoft\\edge\\",
        "\\appdata\\local\\google\\chrome\\",
        "\\appdata\\local\\packages\\",
        "\\appdata\\local\\microsoft\\windows sidebar\\",
        "\\appdata\\roaming\\microsoft\\windows\\recent\\",
    )
    return any(fragment in normalized for fragment in skip_fragments)


_SYSTEM_PARTS = frozenset({"$recycle.bin", "system volume information", "windows", "program files",
                           "program files (x86)"})


def system_by(path: Path, file_attributes: int) -> bool:
    """System: carrying the system attribute, or inside a Windows system folder."""
    return bool(file_attributes & 0x4) or any(part.lower() in _SYSTEM_PARTS for part in path.parts)


def attribute_label(attributes: int, is_hidden: bool = False, is_system: bool = False) -> str:
    labels: list[str] = []
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
        content = str(record.get("content", ""))
        status = record.get("content_status") or content_status_for_extension(extension, content)
        content_scannable = record.get("content_scannable")
        if content_scannable is None:
            content_scannable = extension in CONTENT_EXTENSIONS
        protected = bool(record.get("protected", False)) or status in {
            "protected",
            "password_protected",
            "encrypted",
            "locked",
            "bad_archive",
            "protected_or_uninspectable_archive",
        }
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
                "content": content,
                "acl": record.get("acl") or {},
                "scan_mode": record.get("scan_mode") or scan_mode_for_extension(extension),
                "content_status": status,
                "content_scannable": bool(content_scannable),
                "scan_error": record.get("scan_error", ""),
                "protected": protected,
                "protection_type": record.get("protection_type", ""),
                "owner": record.get("owner", ""),
                "created_at": record.get("created_at", ""),
                "modified_at": record.get("modified_at", ""),
                "accessed_at": record.get("accessed_at", ""),
                "attributes": record.get("attributes", ""),
                "sha256": sha256,
                "file_hash": sha256,
                "content_hash": record.get("content_hash") or content_hash_value(content),
                "scan_completeness": record.get("scan_completeness", "UNKNOWN"),
                "bytes_scanned": int(record.get("bytes_scanned") or 0),
                "total_bytes": int(record.get("total_bytes") or record.get("size") or 0),
                "truncated": bool(record.get("truncated", False)),
                "cache_reused": bool(record.get("cache_reused", False)),
                "incremental_reused": bool(record.get("incremental_reused", False)),
                "reused_preview": record.get("reused_preview"),
                "baseline_result": record.get("baseline_result") if isinstance(record.get("baseline_result"), dict) else None,
                "reuse_key": str(record.get("reuse_key") or ""),
                "skip_reason": str(record.get("skip_reason") or ""),
            }
        )
        # W2.2: every collector's records say what was inspected, from their own fields.
        normalized[-1]["content_coverage"] = content_policy.coverage_state(normalized[-1])
        if isinstance(record.get("database"), dict):
            # D6: a sampled database column carries its table, row count and sample size.
            normalized[-1]["database"] = dict(record["database"])
        if record.get("stable_object_id"):
            # A connector that names its objects by id (SharePoint's drive and item) keeps
            # that name through to the estate, where it - not the path - is the asset: two
            # files of one name in two folders stay two, and a moved file stays one.
            normalized[-1]["stable_object_id"] = str(record["stable_object_id"])
    return normalized
