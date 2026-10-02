"""The scan cache at rest (C0.2): sealed, bounded, and filed by workspace.

A scan keeps what it learned about each file so that an unchanged file is not read
again: a findings entry per analysed file (``<digest>.enc``) and a row per file in the
L1 reuse index (``meta_index.sqlite``). Both hold what a report body holds - the file's
path, owner and ACL, a sanitized preview, every finding - and until C0.2 both were
plaintext JSON under ``DSPM_SCAN_CACHE_DIR``. Anyone who could read the data folder could
read the estate's findings without signing in, a copy of the folder carried them, and
erasing a workspace left its entries behind: they sat in one directory for every
workspace, named by digests nothing could map back to their owner.

What changed, and why each part is the way it is:

- **Sealed with the artifact key.** An entry is ``b"SSC1"`` followed by a Fernet token
  over the zlib-compressed JSON - the authenticated encryption the artifact store and the
  backups already use, and the key (``DSPM_ARTIFACT_KEY``) that already seals report
  bodies, because these entries are report-body data. The token is stored as its raw
  bytes rather than its base64 text: base64 is Fernet's transport encoding, not part of
  what it authenticates, and keeping it would make every entry a third larger on disk.
  ``SSC1`` names the format, so a later one can be told apart rather than guessed.
- **Compressed, then encrypted.** Ciphertext does not compress, so the order is fixed.
  Compression makes an entry's length depend on its content. An entry holds one file's
  own record, so what someone plants in a file is compressed beside nothing but that
  file's metadata, and watching the lengths takes read access to the cache directory -
  the access sealing exists to make worthless. The artifact store chose the same way.
- **Bounded.** An entry is read only up to ``MAX_SEALED_BYTES`` and inflated only up to
  ``MAX_PLAIN_BYTES``; past either it is a miss. Nothing this build writes comes near
  them, so the bounds only stop a damaged or foreign file from deciding how much memory
  a scan allocates.
- **Atomic.** An entry is written under a private name and renamed into place, so a
  reader sees a whole entry or none; the name is unique per write, so two threads never
  share one.
- **Filed by workspace.** Entries live under ``<cache>/tenants/<workspace>/``. The keys
  already carried the workspace, so nothing was ever shared; what the directory adds is
  that erasing a workspace is one subtree delete (``erase_tenant``), as it is for the
  artifact store.
- **What was there before is discarded, not converted.** The previous layout - entries
  in the cache root, in clear - is removed the first time an engine opens the cache, by
  exact name (a cache directory pointed at a shared folder loses nothing else). Each
  workspace directory carries a ``FORMAT`` marker sealed with the current key; one
  written under another format or another key is emptied rather than read. Converting
  would mean reading every plaintext entry once more to keep a cache whose whole value
  is that it can be rebuilt: the first scan after the upgrade reads files again (or
  replays them from the durable database baseline, which is unchanged), and every later
  scan reuses as before.

``DSPM_SCAN_CACHE_ENCRYPT=0`` writes the same layout without the encryption, for an
evaluation install that measured the cost and wants it back; production refuses it.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import shutil
import uuid
import zlib
from contextlib import suppress
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

ENVELOPE_MAGIC = b"SSC1"
FINDINGS_SUFFIX = ".enc"
STAGING_SUFFIX = ".tmp"
TENANTS_DIRNAME = "tenants"
FORMAT_FILENAME = "FORMAT"
# Every entry is compressed on the analysis thread's hot path; level 1 is what the L1
# index already measured as the right trade (82 us at 4.4x against 274 us at 6.1x).
COMPRESSION_LEVEL = 1
# Far above anything a scan writes - an entry is a few kilobytes, a file with ten
# thousand distinct findings a few megabytes - and far below what a damaged or foreign
# file could otherwise make a scan allocate.
MAX_SEALED_BYTES = 32 * 1024 * 1024
MAX_PLAIN_BYTES = 256 * 1024 * 1024

_SEALED_MARKER = b"sentro-scan-cache sealed-v1\n"
_PLAIN_MARKER = b"sentro-scan-cache plain-v1\n"
_CANARY = b"sentro scan cache canary"
_MARKER_MAX_BYTES = 4096

# The layout before C0.2, matched by exact name so nothing else in the directory is touched.
_LEGACY_ENTRY = re.compile(r"^[0-9a-f]{64}(?:\.meta)?\.(?:json|tmp)$")
_LEGACY_INDEX_FILES = frozenset({
    "meta_index.sqlite", "meta_index.sqlite-wal", "meta_index.sqlite-shm", "meta_index.sqlite.rebuild",
})
_LEGACY_WHOLE_INDEX = "index.json"
_LEGACY_WHOLE_INDEX_HEADER = '{"index_version": 1'


class CacheKeyUnavailable(RuntimeError):
    """The key that seals the cache cannot be resolved, so the cache is not used at all."""


class EntryTooLarge(ValueError):
    """An entry beyond the bounds a reader would accept; it is not written."""


def default_cache_dir() -> str:
    """Where the cache lives when a scan names no directory (ScanConfig's default)."""
    return os.getenv("DSPM_SCAN_CACHE_DIR", "data/scan_cache")


def encryption_enabled() -> bool:
    return os.getenv("DSPM_SCAN_CACHE_ENCRYPT", "1").strip().lower() not in {"0", "false", "no", "off"}


class CacheCodec:
    """Turns a cache entry's plaintext into what is stored, and back."""

    __slots__ = ("_fernet",)

    def __init__(self, fernet: Fernet | None) -> None:
        self._fernet = fernet

    @property
    def sealed(self) -> bool:
        return self._fernet is not None

    def seal(self, plain: bytes) -> bytes:
        if len(plain) > MAX_PLAIN_BYTES:
            raise EntryTooLarge("the entry is larger than a reader accepts")
        packed = zlib.compress(plain, COMPRESSION_LEVEL)
        if self._fernet is None:
            stored = packed
        else:
            stored = ENVELOPE_MAGIC + base64.urlsafe_b64decode(self._fernet.encrypt(packed))
        if len(stored) > MAX_SEALED_BYTES:
            raise EntryTooLarge("the entry is larger than a reader accepts")
        return stored

    def open(self, stored: bytes) -> bytes | None:
        """The entry's plaintext, or None when this codec cannot vouch for it.

        None covers an entry too large to read, one sealed with another key, one altered
        after it was sealed, and one in the other format (plaintext while sealing is on).
        Each is a miss. ``zlib.error`` means the bytes were authentic, or plaintext by
        design, and still do not inflate - damage, which the caller may treat as such.
        """
        if not stored or len(stored) > MAX_SEALED_BYTES:
            return None
        stored = bytes(stored)
        if self._fernet is not None:
            if not stored.startswith(ENVELOPE_MAGIC):
                return None
            try:
                packed = self._fernet.decrypt(base64.urlsafe_b64encode(stored[len(ENVELOPE_MAGIC):]))
            except (InvalidToken, ValueError, TypeError):
                return None
        else:
            if stored.startswith(ENVELOPE_MAGIC):
                return None
            packed = stored
        return _inflate(packed)

    def marker(self) -> bytes:
        return _SEALED_MARKER + self.seal(_CANARY) if self.sealed else _PLAIN_MARKER

    def marker_matches(self, data: bytes) -> bool:
        if not self.sealed:
            return data == _PLAIN_MARKER
        if not data.startswith(_SEALED_MARKER):
            return False
        try:
            return self.open(data[len(_SEALED_MARKER):]) == _CANARY
        except zlib.error:
            return False


def _inflate(packed: bytes) -> bytes | None:
    inflater = zlib.decompressobj()
    plain = inflater.decompress(packed, MAX_PLAIN_BYTES)
    if inflater.unconsumed_tail:
        return None  # larger than anything this build writes: not read
    if not inflater.eof:
        raise zlib.error("the entry ends before its compressed stream does")
    return plain


def codec_from_environment() -> CacheCodec:
    """The codec this process seals with: the artifact key, unless sealing is turned off."""
    if not encryption_enabled():
        return CacheCodec(None)
    from backend.artifacts import artifact_key

    try:
        return CacheCodec(Fernet(artifact_key()))
    except (RuntimeError, ValueError, OSError) as exc:
        # A cache it cannot seal is a cache it does not use - never one written in clear.
        raise CacheKeyUnavailable(f"the scan cache is not used: its key is unavailable ({type(exc).__name__})") from exc


def tenant_dir_name(tenant_id: str) -> str:
    """A workspace's directory name: readable, and unique to the exact id.

    The digest keeps two ids that differ only in case - one directory on Windows - or in
    characters a path cannot hold apart, and it means no id can reach outside ``tenants``.
    """
    text = str(tenant_id or "default")
    readable = re.sub(r"[^a-z0-9_-]", "", text.lower())[:32] or "tenant"
    return f"{readable}-{hashlib.sha256(text.encode('utf-8')).hexdigest()[:16]}"


def tenant_cache_dir(cache_dir: str | os.PathLike, tenant_id: str) -> Path:
    return Path(cache_dir).expanduser().resolve() / TENANTS_DIRNAME / tenant_dir_name(tenant_id)


def prepare_tenant_dir(cache_dir: str | os.PathLike, tenant_id: str, codec: CacheCodec) -> Path:
    """The workspace's cache directory, ready to read and write with ``codec``.

    Removes the pre-C0.2 layout from the cache root, and empties a workspace directory
    whose entries were written in another format or under another key. Raises OSError
    when the directory cannot be made or its marker cannot be read; the engine then
    scans without a cache.
    """
    root = Path(cache_dir).expanduser().resolve()
    purge_legacy_layout(root)
    directory = root / TENANTS_DIRNAME / tenant_dir_name(tenant_id)
    directory.mkdir(parents=True, exist_ok=True)
    marker = directory / FORMAT_FILENAME
    try:
        with open(marker, "rb") as handle:
            current = handle.read(_MARKER_MAX_BYTES)
    except FileNotFoundError:
        current = None
    if current is not None and codec.marker_matches(current):
        return directory
    _clear_directory(directory)
    write_entry(marker, codec.marker())
    return directory


def _clear_directory(directory: Path) -> int:
    removed = 0
    try:
        entries = list(os.scandir(directory))
    except OSError:
        return 0
    for entry in entries:
        if entry.is_file(follow_symlinks=False):
            try:
                os.unlink(entry.path)
                removed += 1
            except OSError:
                continue  # held open by another engine; its entries fail to open and miss
    return removed


def purge_legacy_layout(root: Path) -> int:
    """Remove the plaintext entries the pre-C0.2 cache kept in its root, by exact name."""
    try:
        entries = list(os.scandir(root))
    except OSError:
        return 0
    removed = 0
    for entry in entries:
        name = entry.name
        if not entry.is_file(follow_symlinks=False):
            continue
        legacy = _LEGACY_ENTRY.match(name) is not None or name in _LEGACY_INDEX_FILES
        if not legacy and name == _LEGACY_WHOLE_INDEX:
            legacy = _is_legacy_whole_index(Path(entry.path))
        if legacy:
            try:
                os.unlink(entry.path)
                removed += 1
            except OSError:
                continue  # an older process still holds it; the next engine tries again
    return removed


def _is_legacy_whole_index(path: Path) -> bool:
    """The whole-document index B1.3a replaced - but only a file that begins exactly as it did."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(len(_LEGACY_WHOLE_INDEX_HEADER)).decode("utf-8", "replace")
    except OSError:
        return False
    return head == _LEGACY_WHOLE_INDEX_HEADER


def read_entry(path: Path) -> bytes | None:
    """A stored entry, read no further than the bound; an oversized one is removed."""
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_SEALED_BYTES + 1)
    except OSError:
        return None
    if len(data) > MAX_SEALED_BYTES:
        discard(path)
        return None
    return data


def write_entry(path: Path, data: bytes) -> None:
    """Write under a private name and rename into place. Raises OSError."""
    staging = path.with_name(f"{path.name}.{os.getpid()}.{uuid.uuid4().hex[:12]}{STAGING_SUFFIX}")
    try:
        with open(staging, "wb") as out:
            out.write(data)
        os.replace(staging, path)
    finally:
        with suppress(OSError):
            staging.unlink(missing_ok=True)


def discard(path: Path) -> None:
    with suppress(OSError):
        path.unlink(missing_ok=True)


def erase_tenant(tenant_id: str, cache_dir: str | os.PathLike | None = None) -> int:
    """Remove a workspace's whole cache directory; returns the number of files removed.

    Raises when the directory cannot be removed - an erasure that reports success while
    the workspace's entries are still on disk is worse than one that fails loudly.
    """
    base = cache_dir if cache_dir else (default_cache_dir() or "data/scan_cache")
    target = tenant_cache_dir(base, tenant_id)
    if not target.exists():
        return 0
    removed = sum(1 for path in target.rglob("*") if path.is_file())
    shutil.rmtree(target)
    return removed
