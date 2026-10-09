"""What a scan reads of a file, what it calls the file by, and what it says it covered
(scaling roadmap W2.2: bytes read follow bytes inspected).

Before W2.2 every fresh file was read whole to hash it - a 40 GB disk image as much as a
4 KB note - so a first scan of 3 TB read 3 TB, and a text file was decoded up to 100 MiB
into one string. Now:

- **Inspected and within its cap** (text up to ``DSPM_TEXT_SCAN_MAX_BYTES``, 16 MiB; a
  document or image up to ``DSPM_DOCUMENT_SCAN_MAX_BYTES``, 64 MiB): read once. The same
  read gives the text and the whole-file SHA-256 - the identity the evidence reveal checks.
- **Text over its cap**: the first ``cap`` bytes are inspected (PARTIAL_CONTENT) and the
  file is called ``head:<cap>:<SHA-256 of those bytes>`` - a cryptographic digest of
  exactly the bytes its findings came from. The reveal reads the same bytes again and
  checks them. Nothing past the cap is read.
- **Not inspected** (a type without content rules, a document over its cap, an archive
  not opened, a sealed file): identity by ``DSPM_HASH_POLICY``.
  - ``meta`` (default): ``meta:<digest of size, mtime, file id>``. No content is read,
    and the identity is not cryptographic: it changes when the file's metadata does.
  - ``sampled``: ``sampled:<SHA-256 of size + first and last MiB>``, 2 MiB read.
  - ``full``: the whole-file SHA-256, every byte read - the behaviour before W2.2.
    Under ``full`` an over-cap text file is also called by its whole-file SHA-256.

A rescan reuses an unchanged file (path, size, mtime) whatever its identity, so none of
this is read again until the file changes.

Coverage: every file record says how much of it was inspected, in one of five states,
and never claims more than was read:

- ``FULL_CONTENT``: the whole file's content inspected (an empty file included).
- ``PARTIAL_CONTENT``: a bounded part inspected - a cap was hit, a document's text was cut
  short, a part of it was skipped.
- ``METADATA_ONLY``: a type the scan does not read content from, or content it cannot
  read by design (sealed, no text layer).
- ``SKIPPED_POLICY``: content the scan could read but chose not to - over a size cap,
  content reading off.
- ``FAILED``: the read or the extraction failed.
"""
from __future__ import annotations

import hashlib
import os

FULL_CONTENT = "FULL_CONTENT"
PARTIAL_CONTENT = "PARTIAL_CONTENT"
METADATA_ONLY = "METADATA_ONLY"
SKIPPED_POLICY = "SKIPPED_POLICY"
FAILED = "FAILED"
COVERAGE_STATES = (FULL_CONTENT, PARTIAL_CONTENT, METADATA_ONLY, SKIPPED_POLICY, FAILED)

DEFAULT_TEXT_CAP_BYTES = 16 * 1024 * 1024
DEFAULT_DOCUMENT_CAP_BYTES = 64 * 1024 * 1024
SAMPLE_BYTES = 1024 * 1024
HASH_POLICIES = ("meta", "sampled", "full")

# content_status values that mean the read or the extraction failed.
_FAILED_STATUSES = {"unreadable", "not_extracted", "bad_archive"}
# ... that the scan chose not to read content it could have read.
_POLICY_STATUSES = {"over_size_cap", "not_requested", "not_inspected", "offline_not_recalled"}
# ... that there is nothing more to read by design: the file is sealed or holds no text.
_BY_DESIGN_STATUSES = {"protected", "password_protected", "protected_or_uninspectable_archive",
                       "no_text_layer", "metadata_only"}


def _env_bytes(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name) or default)
    except ValueError:
        value = default
    return max(1, value)


def text_cap_bytes() -> int:
    """``DSPM_TEXT_SCAN_MAX_BYTES``: how much of a text file is inspected (16 MiB)."""
    return _env_bytes("DSPM_TEXT_SCAN_MAX_BYTES", DEFAULT_TEXT_CAP_BYTES)


def document_cap_bytes() -> int:
    """``DSPM_DOCUMENT_SCAN_MAX_BYTES``: the largest document or image read for its text
    (64 MiB). A document cannot be inspected from a prefix - its directory is at the end -
    so a larger one is not read at all: SKIPPED_POLICY, said on its record."""
    return _env_bytes("DSPM_DOCUMENT_SCAN_MAX_BYTES", DEFAULT_DOCUMENT_CAP_BYTES)


def hash_policy() -> str:
    """``DSPM_HASH_POLICY`` for files whose content is not read whole: meta, sampled, full."""
    value = str(os.getenv("DSPM_HASH_POLICY") or "meta").strip().lower()
    return value if value in HASH_POLICIES else "meta"


def meta_identity(size: int, mtime: object, file_id: object = "") -> str:
    """The identity of a file read for none of its content: its size, its modification
    time and - where the source has one - its file id. Not cryptographic, and labelled so."""
    raw = f"{int(size or 0)}|{mtime or ''}|{file_id or ''}"
    return "meta:" + hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:32]


def sampled_identity(size: int, head: bytes, tail: bytes) -> str:
    digest = hashlib.sha256(str(int(size or 0)).encode("ascii"))
    digest.update(b"\0")
    digest.update(head)
    digest.update(b"\0")
    digest.update(tail)
    return "sampled:" + digest.hexdigest()


def head_identity(cap: int, prefix_digest: str) -> str:
    """The identity of a file inspected up to ``cap`` bytes: the SHA-256 of those bytes."""
    return f"head:{int(cap)}:{prefix_digest}" if prefix_digest else ""


def head_identity_cap(identity: str) -> int | None:
    """The cap a ``head:`` identity was taken at, so a re-read takes the same bytes."""
    if not str(identity or "").startswith("head:"):
        return None
    try:
        return int(str(identity).split(":", 2)[1])
    except (IndexError, ValueError):
        return None


def is_whole_file_digest(identity: str) -> bool:
    text = str(identity or "")
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text.lower())


def needs_sample(size: int) -> bool:
    return hash_policy() == "sampled" and int(size or 0) > 2 * SAMPLE_BYTES


def coverage_state(record: dict) -> str:
    """The record's coverage, one of COVERAGE_STATES; "" for a folder."""
    if record.get("is_dir"):
        return ""
    status = str(record.get("content_status") or "").strip().lower()
    completeness = str(record.get("scan_completeness") or "").strip().upper()
    if status in _FAILED_STATUSES:
        return FAILED
    if status in _POLICY_STATUSES:
        return SKIPPED_POLICY
    if status in _BY_DESIGN_STATUSES or record.get("protected"):
        return METADATA_ONLY
    if completeness == "PARTIAL" or record.get("truncated"):
        return PARTIAL_CONTENT
    try:
        size = int(record.get("size") or record.get("total_bytes") or 0)
        scanned = int(record.get("bytes_scanned") or 0)
    except (TypeError, ValueError):
        size, scanned = 0, 0
    if completeness in {"FULL", "COMPLETE"} and (scanned > 0 or size == 0 or record.get("content")):
        return FULL_CONTENT
    if record.get("scan_error"):
        return FAILED
    return METADATA_ONLY


def coverage_counts(records) -> dict[str, int]:
    counts = dict.fromkeys(COVERAGE_STATES, 0)
    for record in records:
        state = record.get("content_coverage") or coverage_state(record)
        if state in counts:
            counts[state] += 1
    return counts
