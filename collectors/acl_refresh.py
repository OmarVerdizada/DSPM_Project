"""When a file reused from an earlier scan has its access read again (W3.6, E14).

A file whose size and modified time are unchanged is reused: its findings, its owner and
its ACL come from the snapshot of the scan that last read it. An ACL edit does not move a
file's modified time, so a permission change stayed invisible for as long as the file did
not change. Reading every file's ACL on every scan is a round trip per file per scan. The
policy in between:

- **folders** - where inheritance comes from - have their ACL read on every scan, once each;
  a reused file whose parent folder's ACL is not what it was when the file's own ACL was
  read is read again;
- a file whose ACL has **explicit entries** is read again on every scan. An ACL that does
  not say which entries are inherited (the PowerShell paths) or that could not be read is
  not treated as explicit: re-reading every such file every scan is the cost this policy
  exists to avoid, and the folder check and the full refresh still reach it;
- **every** file is read again at least every ``DSPM_ACL_FULL_REFRESH_DAYS`` (7; 0 reads
  every file's ACL on every scan), spread over that period by path so an estate does not
  re-read itself on one night.

A file read again has ``acl_checked_at`` and ``acl_parent_digest`` stamped, which the next
scan's snapshot carries. A snapshot written before this policy has neither: its file is
read again once.
"""
from __future__ import annotations

import hashlib
import json
import os
import zlib
from datetime import datetime, timedelta, timezone

DEFAULT_FULL_REFRESH_DAYS = 7.0

NEVER_CHECKED = "never_checked"
FULL_REFRESH = "full_refresh"
EXPLICIT_ENTRIES = "explicit_entries"
FOLDER_CHANGED = "folder_changed"


def full_refresh_days() -> float:
    """``DSPM_ACL_FULL_REFRESH_DAYS``: how long a reused file's ACL may be replayed at most."""
    raw = os.getenv("DSPM_ACL_FULL_REFRESH_DAYS", "").strip()
    if not raw:
        return DEFAULT_FULL_REFRESH_DAYS
    try:
        return max(0.0, min(float(raw), 365.0))
    except ValueError:
        return DEFAULT_FULL_REFRESH_DAYS


def acl_digest(acl) -> str:
    """A stable digest of an ACL: who may do what, and which entries are inherited."""
    if not isinstance(acl, dict) or not acl:
        return ""
    entries = acl.get("entries") if isinstance(acl.get("entries"), list) else []
    canonical = {
        "owner": str(acl.get("owner") or ""),
        "principals": sorted(str(item) for item in acl.get("principals") or []),
        "permissions": sorted(str(item) for item in acl.get("permissions") or []),
        "entries": sorted(json.dumps(entry, sort_keys=True, default=str) for entry in entries),
    }
    return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode("utf-8")).hexdigest()[:32]


def has_explicit_entries(acl) -> bool:
    """Whether an ACL holds an entry set on the file itself. Only an entry that says it is
    not inherited counts: an ACL without inheritance flags, or none at all, cannot say."""
    if not isinstance(acl, dict):
        return False
    entries = acl.get("entries")
    if not isinstance(entries, list):
        return False
    return any(isinstance(entry, dict) and entry.get("inherited") is False for entry in entries)


def _parse(value) -> datetime | None:
    try:
        moment = datetime.fromisoformat(str(value or ""))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _spread(path: str) -> float:
    """Between 0.5 and 1.0 of the refresh period, fixed per path."""
    return 0.5 + (zlib.crc32(str(path).casefold().encode("utf-8")) % 1000) / 2000.0


def refresh_reason(snapshot: dict, *, path: str, parent_digest: str, now: datetime | None = None) -> str:
    """Why a reused file's ACL is read again on this scan - '' when its snapshot's stands."""
    checked = _parse(snapshot.get("acl_checked_at"))
    if checked is None:
        return NEVER_CHECKED
    days = full_refresh_days()
    moment = now or datetime.now(timezone.utc)
    if days <= 0 or moment - checked >= timedelta(days=days * _spread(path)):
        return FULL_REFRESH
    if has_explicit_entries(snapshot.get("acl")):
        return EXPLICIT_ENTRIES
    if parent_digest and str(snapshot.get("acl_parent_digest") or "") != parent_digest:
        return FOLDER_CHANGED
    return ""


def stamp(record: dict, *, parent_digest: str, now: datetime | None = None) -> dict:
    """Mark a record's ACL as read now, under a parent folder whose ACL has this digest."""
    record["acl_checked_at"] = (now or datetime.now(timezone.utc)).isoformat()
    record["acl_parent_digest"] = parent_digest
    return record


class RefreshTally:
    """What the policy did on one scan: folders read, files read again by reason, replayed."""

    def __init__(self) -> None:
        self.folders_read = 0
        self.files_reread: dict[str, int] = {}
        self.files_replayed = 0

    def reread(self, reason: str) -> None:
        self.files_reread[reason] = self.files_reread.get(reason, 0) + 1

    def to_dict(self) -> dict:
        """Counts only, so a partitioned scan's units add up to the scan's."""
        return {"folders_read": self.folders_read,
                "files_reread": dict(sorted(self.files_reread.items())),
                "files_reread_total": sum(self.files_reread.values()),
                "files_replayed": self.files_replayed}
