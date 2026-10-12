"""Advanced scan scope: what a scan reads, decided before it reads it.

A scan's scope is part of its definition - stored with the request, so a resumed, retried,
scheduled or queued run, and every incremental run after it, applies exactly the same
rules. Every rule is optional; with none, a scan is what it always was.

**The rules**

- ``exclude_extensions`` - files with these extensions are never scanned (``.iso``,
  ``.vhdx``). The extension policy's allow-list is the include side, as before.
- ``min_size_bytes`` / ``max_size_bytes`` - files smaller or larger are not opened.
- ``include_paths`` - only these folders, and what is under them, are walked.
- ``exclude_paths`` - these folders (or files), and everything under them, are skipped.
- ``modified_after`` - files last modified before this date (UTC) are not opened.

**Precedence** is fixed, and an exclusion always wins: a file is in scope when it is
inside an included folder (or no folder is included), outside every excluded folder,
its extension is not excluded -
and, when the extension policy names extensions, is one of them - its size is within the
limits, and it was modified on or after the date. Paths compare without regard to case
and to ``\\`` versus ``/``, as Windows file servers compare them.

**Where each rule is applied** - the earliest point the facts it needs exist:

- folder rules (excluded and included paths): before a folder is listed,
  so its subtree is never enumerated - by the walk and by the partition planner alike;
- name rules (path, extension): as a file is listed - before a stat, an open, a hash, an
  extraction, a classification or a database row;
- metadata rules (size, modified date): as soon as size and time are known - from the
  listing itself on SMB and WinRM, from one ``stat`` on a local disk - before the file is
  opened.

Paths are relative to the scan's target for a file-server scan - ``Finance/Archive`` under
the local folder, or ``share/folder`` on an SMB server - and absolute (``C:\\Users\\...`` or
``\\\\server\\share\\...``) on an endpoint, whose folders are already chosen by its paths.

There is no folder-name rule: a scan reads every folder of its target, narrowed only by
path, type, size and date - what the console offers.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Iterable

from collectors.file_scanner import normalize_one_extension

# Reasons a file or folder is out of scope, as diagnostics and the console name them.
EXCLUDED_FOLDER = "excluded_folder"
OUTSIDE_INCLUDED = "outside_included_folders"
EXTENSION = "extension"
TOO_SMALL = "smaller_than_minimum"
TOO_LARGE = "larger_than_maximum"
MODIFIED_BEFORE = "modified_before_date"

MAX_SCOPE_BYTES = 1 << 44  # 16 TiB: larger than any single file a scan meets
MAX_PATH_LENGTH = 1024
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_DRIVE = re.compile(r"^[a-z]:(/|$)", re.IGNORECASE)


# ---------------------------------------------------------------- validation (the API's)

def clean_extensions(values: Iterable[str] | None) -> list[str]:
    """Canonical extensions (``.iso``), each a valid one; anything else is an error, not
    silently dropped - an exclusion that matches nothing would read as working."""
    found: set[str] = set()
    for item in values or []:
        for token in re.split(r"[,\s;|]+", str(item or "")):
            if not token.strip():
                continue
            extension = normalize_one_extension(token)
            if not extension:
                raise ValueError(f"{token.strip()!r} is not a file extension (for example .iso or vhdx)")
            found.add(extension)
    return sorted(found)


def clean_path(value: str, *, absolute: bool | None) -> str:
    """One folder or file path as the operator wrote it, tidied: separators kept as typed,
    no control characters, no ``..``, no wildcards - a path names one folder or file.
    ``absolute`` True requires a drive or UNC path, False refuses a drive path, None
    checks neither (the request's field check; the scan type decides later)."""
    text = _CONTROL.sub("", str(value or "")).strip().strip('"').strip()
    if not text:
        return ""
    if len(text) > MAX_PATH_LENGTH:
        raise ValueError(f"path is longer than {MAX_PATH_LENGTH} characters: {text[:40]}...")
    if any(char in text for char in "*?"):
        raise ValueError(f"{text!r}: a path cannot hold wildcards - name the folder itself")
    parts = [part for part in re.split(r"[\\/]+", text) if part]
    if ".." in parts:
        raise ValueError(f"{text!r}: a path cannot climb out of the scan with '..'")
    unc = text.startswith(("\\\\", "//"))
    drive = bool(_DRIVE.match(text.replace("\\", "/")))
    if absolute is True and not (unc or drive):
        raise ValueError(f"{text!r}: an endpoint path is absolute, like C:\\Users\\name\\Downloads or "
                         "\\\\server\\share\\folder")
    if absolute is False and drive:
        raise ValueError(f"{text!r}: a file-server path is relative to the scan's target, like "
                         "Finance/Archive (or share/folder on an SMB server)")
    return text


def clean_paths(values: Iterable[str] | None, *, absolute: bool | None) -> list[str]:
    seen: dict[str, str] = {}
    for value in values or []:
        cleaned = clean_path(value, absolute=absolute)
        if cleaned:
            seen.setdefault(normalize_path(cleaned, absolute=bool(absolute)), cleaned)
    return list(seen.values())


def unc_to_share_path(path: str, server: str) -> str:
    """``\\\\server\\share\\folder`` -> ``share/folder`` when it names this scan's server; an
    SMB scan's paths are share-relative. Any other path is returned unchanged."""
    text = path.replace("\\", "/")
    if not text.startswith("//"):
        return path
    parts = [part for part in text.split("/") if part]
    if not parts or parts[0].casefold() != str(server or "").strip().casefold():
        raise ValueError(f"{path!r} names another server than the one this scan reads")
    return "/".join(parts[1:])


# ---------------------------------------------------------------- matching (the collectors')

def normalize_path(value: str, *, absolute: bool) -> str:
    """The form paths are compared in: ``/`` separators, case-folded, no trailing ``/``; a
    relative one has no leading ``/`` either, a UNC one keeps its ``//``."""
    text = str(value or "").strip().replace("\\", "/")
    unc = text.startswith("//")
    text = re.sub(r"/{2,}", "/", text)
    text = text.rstrip("/") if absolute else text.strip("/")
    if unc:
        text = "/" + text if text.startswith("/") else "//" + text
    return text.casefold()


def _under(path: str, prefix: str) -> bool:
    """Whether ``path`` is ``prefix`` or inside it. The empty path - a relative scope's
    root - holds everything."""
    return prefix == "" or path == prefix or path.startswith(prefix + "/")


def _epoch(value) -> float | None:
    """A modification time as seconds since the epoch, from what collectors carry."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return moment.timestamp()
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return (moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)).timestamp()


@dataclass(frozen=True)
class ScopeRules:
    """A scan's scope, compiled for matching. Built once per collector from the scan's
    canonical rules (:func:`canonical`); every method is pure and thread-safe."""

    exclude_extensions: frozenset = frozenset()
    min_size: int | None = None
    max_size: int | None = None
    include_paths: tuple = ()
    exclude_paths: tuple = ()
    modified_after: float | None = None
    absolute: bool = False

    @classmethod
    def from_dict(cls, data: dict | None) -> "ScopeRules":
        data = data if isinstance(data, dict) else {}
        absolute = bool(data.get("absolute"))
        after = data.get("modified_after")
        threshold = None
        if after:
            day = date.fromisoformat(str(after)[:10])
            threshold = datetime(day.year, day.month, day.day, tzinfo=timezone.utc).timestamp()
        return cls(
            exclude_extensions=frozenset(str(item).casefold() for item in data.get("exclude_extensions") or ()),
            min_size=int(data["min_size_bytes"]) if data.get("min_size_bytes") not in (None, "") else None,
            max_size=int(data["max_size_bytes"]) if data.get("max_size_bytes") not in (None, "") else None,
            include_paths=tuple(normalize_path(item, absolute=absolute) for item in data.get("include_paths") or ()),
            exclude_paths=tuple(normalize_path(item, absolute=absolute) for item in data.get("exclude_paths") or ()),
            modified_after=threshold,
            absolute=absolute,
        )

    @property
    def active(self) -> bool:
        return bool(self.exclude_extensions or self.min_size is not None or self.max_size is not None
                    or self.include_paths or self.exclude_paths or self.modified_after is not None)

    @property
    def needs_metadata(self) -> bool:
        """Whether a file's size or time decides it - the rules a name alone cannot."""
        return self.min_size is not None or self.max_size is not None or self.modified_after is not None

    def path_of(self, value: str) -> str:
        return normalize_path(value, absolute=self.absolute)

    def folder_reason(self, path: str) -> str:
        """Why a folder is not walked ("" when it is). ``path`` is in the scope's form."""
        if not self.active:
            return ""
        if any(_under(path, excluded) for excluded in self.exclude_paths):
            return EXCLUDED_FOLDER
        if self.include_paths and not any(_under(path, item) or _under(item, path) for item in self.include_paths):
            return OUTSIDE_INCLUDED
        return ""

    def file_name_reason(self, path: str, extension: str) -> str:
        """Why a file is out of scope by its path and name alone - no stat needed."""
        if not self.active:
            return ""
        if any(_under(path, excluded) for excluded in self.exclude_paths):
            return EXCLUDED_FOLDER
        if self.include_paths and not any(_under(path, item) for item in self.include_paths):
            return OUTSIDE_INCLUDED
        if self.exclude_extensions and str(extension or "").casefold() in self.exclude_extensions:
            return EXTENSION
        return ""

    def file_meta_reason(self, size, modified) -> str:
        """Why a file is out of scope by its size or modification time. An unknown value
        never excludes: a rule that cannot be judged keeps the file."""
        if size is not None:
            if self.min_size is not None and int(size) < self.min_size:
                return TOO_SMALL
            if self.max_size is not None and int(size) > self.max_size:
                return TOO_LARGE
        if self.modified_after is not None:
            moment = _epoch(modified)
            if moment is not None and moment < self.modified_after:
                return MODIFIED_BEFORE
        return ""

    def file_reason(self, path: str, extension: str, size=None, modified=None) -> str:
        return self.file_name_reason(path, extension) or self.file_meta_reason(size, modified)


NO_RULES = ScopeRules()


def rules_for(data) -> ScopeRules:
    if isinstance(data, ScopeRules):
        return data
    return ScopeRules.from_dict(data) if data else NO_RULES


# ---------------------------------------------------------------- the scan definition

def canonical(scope: dict | None, *, absolute: bool) -> dict | None:
    """The scope a scan carries in its configuration: only the rules that are set, in one
    spelling, so equal scopes compare and digest equal. ``None`` when nothing is set."""
    scope = scope if isinstance(scope, dict) else {}
    rules: dict = {}
    if scope.get("exclude_extensions"):
        rules["exclude_extensions"] = sorted({str(item).casefold() for item in scope["exclude_extensions"]})
    for key in ("min_size_bytes", "max_size_bytes"):
        if scope.get(key) not in (None, ""):
            rules[key] = int(scope[key])
    for key in ("include_paths", "exclude_paths"):
        if scope.get(key):
            rules[key] = sorted({normalize_path(item, absolute=absolute) for item in scope[key]} - {""})
    if scope.get("modified_after"):
        rules["modified_after"] = str(scope["modified_after"])[:10]
    rules = {key: value for key, value in rules.items() if value not in ([], None)}
    if not rules:
        return None
    rules["absolute"] = bool(absolute)
    return rules


def digest(rules: dict | None) -> str:
    """A stable name for a canonical scope - the incremental scope key's part of it."""
    if not rules:
        return ""
    return hashlib.sha256(json.dumps(rules, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()[:16]


def rule_count(rules: dict | None) -> int:
    """How many rules a canonical scope holds - one per path and extension, one per limit."""
    if not rules:
        return 0
    count = 0
    for key, value in rules.items():
        if key == "absolute":
            continue
        count += len(value) if isinstance(value, list) else 1
    return count


# ---------------------------------------------------------------- what the scope did

# W3.6 (decision D4): folders a scan did not enter for a reason other than its scope rules.
# A depth limit exists only when one is configured; system folders (Windows, Program Files,
# the recycle bin, ...) are never walked. Both are counted and said, like a scope rule's.
NOT_ENTERED_DEPTH = "depth_limit"
NOT_ENTERED_SYSTEM = "system_path"

# Why a scan's coverage is not full: what its ``limited_by`` can name.
LIMITED_BY_DEPTH = "depth"
LIMITED_BY_SCOPE = "scope"
LIMITED_BY_SYSTEM = "system_paths"


class ScopeTally:
    """What a collector left out, and why - counted as it happens, thread-safe."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._files: Counter = Counter()
        self._folders: Counter = Counter()
        self._not_entered: Counter = Counter()

    def file(self, reason: str) -> None:
        with self._lock:
            self._files[reason] += 1

    def folder(self, reason: str) -> None:
        with self._lock:
            self._folders[reason] += 1

    def not_entered(self, reason: str, count: int = 1) -> None:
        """A folder the scan did not enter: past its depth limit, or a system folder."""
        with self._lock:
            self._not_entered[reason] += int(count)

    def merge_counts(self, files: dict | None, folders: dict | None, not_entered: dict | None = None) -> None:
        with self._lock:
            self._files.update({str(key): int(value or 0) for key, value in (files or {}).items()})
            self._folders.update({str(key): int(value or 0) for key, value in (folders or {}).items()})
            self._not_entered.update({str(key): int(value or 0) for key, value in (not_entered or {}).items()})

    def to_dict(self, rules: dict | None, *, depth_limit: int | None = None) -> dict:
        """The scan diagnostics' ``scope`` block. Files under a skipped folder were never
        listed, so they are not counted - the folders are.

        Every scan has one since W3.6: ``active`` says whether scope rules were set,
        ``depth_limit`` is the configured limit (None: every folder is entered), and
        ``coverage`` is ``full`` only when nothing was left out - no folder past the depth
        limit, no file or folder out of scope, no system folder."""
        with self._lock:
            files, folders, not_entered = dict(self._files), dict(self._folders), dict(self._not_entered)
        block = {
            "active": bool(rules),
            "rules": dict(rules or {}),
            "rule_count": rule_count(rules),
            "excluded_files": sum(files.values()),
            "excluded_by": dict(sorted(files.items())),
            "skipped_folders": sum(folders.values()),
            "skipped_folders_by": dict(sorted(folders.items())),
            "depth_limit": int(depth_limit) if depth_limit is not None else None,
            "folders_not_entered": sum(not_entered.values()),
            "not_entered_by": dict(sorted(not_entered.items())),
        }
        return settle_block(block)


def limited_by(block: dict | None) -> list[str]:
    """Why a scan's coverage is not full, from its scope block - empty when it is."""
    if not isinstance(block, dict):
        return []
    reasons = []
    not_entered = block.get("not_entered_by") if isinstance(block.get("not_entered_by"), dict) else {}
    if int(not_entered.get(NOT_ENTERED_DEPTH) or 0) > 0:
        reasons.append(LIMITED_BY_DEPTH)
    if int(block.get("excluded_files") or 0) > 0 or int(block.get("skipped_folders") or 0) > 0:
        reasons.append(LIMITED_BY_SCOPE)
    if int(not_entered.get(NOT_ENTERED_SYSTEM) or 0) > 0:
        reasons.append(LIMITED_BY_SYSTEM)
    return reasons


def settle_block(block: dict) -> dict:
    """Set a block's ``limited_by`` and ``coverage`` from its counts."""
    reasons = limited_by(block)
    block["limited_by"] = reasons
    block["coverage"] = "limited" if reasons else "full"
    return block


def settle(diagnostics: dict, *, depth_limit: int | None) -> dict:
    """A scan's diagnostics with its scope block describing the scan as a whole: the
    configured depth limit - a partition's walk is told a limit relative to its own folder -
    and the coverage its merged counts give."""
    block = diagnostics.get("scope") if isinstance(diagnostics.get("scope"), dict) else ScopeTally().to_dict(None)
    block = dict(block)
    block["depth_limit"] = int(depth_limit) if depth_limit is not None else None
    diagnostics["scope"] = settle_block(block)
    return diagnostics


def prune_allowed(diagnostics: dict | None) -> bool:
    """Whether a named scan may take the assets it did not see out of the estate (W3.6).

    A scan that did not enter every folder its earlier runs entered - a depth limit that
    left folders out, scope rules that left files or folders out - did not see them, and
    what it did not see is not gone. System folders are never entered by any scan, so
    their being skipped does not stop the prune."""
    block = (diagnostics or {}).get("scope") if isinstance(diagnostics, dict) else None
    return not ({LIMITED_BY_DEPTH, LIMITED_BY_SCOPE} & set(limited_by(block)))


def merge_diagnostics(parts: list[dict]) -> dict:
    """One scan's ``scope`` block from its partitions': the rules are the scan's (every
    partition carries the same), the counts add up. The depth limit is the first
    partition's here; the scan's own is set by ``settle``."""
    parts = [part for part in parts if isinstance(part, dict)]
    if not parts:
        return {}
    tally = ScopeTally()
    for part in parts:
        tally.merge_counts(part.get("excluded_by"), part.get("skipped_folders_by"), part.get("not_entered_by"))
    rules = next((part.get("rules") for part in parts if part.get("rules")), None)
    return tally.to_dict(rules, depth_limit=parts[0].get("depth_limit"))


def summary_fields(diagnostics: dict | None) -> dict:
    """What a scan's scope adds to its summary - the history row's line.

    Every scan with a scope block says its coverage (W3.6): ``coverage`` is ``full`` or
    ``limited``, ``coverage_limited_by`` names why, ``depth_limit`` is the configured one
    (None: none), and the folders it did not enter are counted by reason. A scoped scan
    also says its rules, as before. The counts add up across partitions; ``scope`` and
    the coverage describe the scan, and finalize sets them from the merged block."""
    block = (diagnostics or {}).get("scope") if isinstance(diagnostics, dict) else None
    if not isinstance(block, dict):
        return {}
    not_entered = block.get("not_entered_by") if isinstance(block.get("not_entered_by"), dict) else {}
    reasons = limited_by(block)
    fields = {
        "coverage": "limited" if reasons else "full",
        "coverage_limited_by": reasons,
        "depth_limit": block.get("depth_limit"),
        "folders_not_entered_by_depth": int(not_entered.get(NOT_ENTERED_DEPTH) or 0),
        "system_folders_skipped": int(not_entered.get(NOT_ENTERED_SYSTEM) or 0),
    }
    if block.get("active"):
        fields.update({
            "excluded_by_scope": int(block.get("excluded_files") or 0),
            "folders_skipped_by_scope": int(block.get("skipped_folders") or 0),
            "scope": {"rule_count": int(block.get("rule_count") or 0), "rules": dict(block.get("rules") or {})},
        })
    return fields
