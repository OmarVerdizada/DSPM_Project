"""Who can read or write a file, from the ACL a collector read (D7).

A collector records ``acl = {owner, principals, permissions, entries}``. ``entries``
(one per access-control entry: principal, SID, rights, mask, allow or deny, inherited)
is what this reads; ``principals``/``permissions`` - the parallel lists older
collectors and older scans carry - are read as allow entries when there are no
entries.

What changed with D7, and why:

* A **deny** entry was read like an allow. "Everyone: Deny" made a file look broadly
  readable and writable. Now an allow for a principal is cancelled by a deny of the
  same right for the same principal (group nesting is not resolved: a deny for a group
  does not cancel an allow for one of its members' groups - Windows would, so this
  errs toward reporting access).
* Broad groups were matched by **substring**, so "Remote Desktop Users" and "Power
  Users" counted as "Users". Now they are matched by well-known SID, or by the exact
  account name when a collector gave no SID.
* ``writable`` meant *anyone* could write - the owner or Administrators made nearly
  every file "writable". It now means a **broad** group can write, which is the
  exposure the risk engine describes ("remove broad or writable groups").
* Service and indexer identities (NT SERVICE, IIS, NETWORK/LOCAL SERVICE, and the
  accounts named in ``DSPM_INDEXER_PRINCIPALS``) are flagged: a search indexer that
  can read everything is broad access by another name.

What the M4 exit review changed, and why:

* A deny cancelled a whole verdict, not the rights it named: "Domain Users: Allow
  Modify, Deny Delete" read as "cannot write", because Delete is one of the write-ish
  bits. Entries are now evaluated as access masks, bit by bit, the way Windows does:
  what the allows grant less what an earlier deny took. "Can write" means writing or
  appending the data survives (or changing the permissions or the owner, either of which
  lets the holder grant itself write) - not that every write-ish bit does.
* The ``inherited`` flag was recorded and never read, so an inherited "Everyone: Deny
  Read" outranked an explicit "Everyone: Allow Read" on the file - which Windows grants.
  Entries are evaluated in Windows' canonical order: explicit denies, explicit allows,
  then the inherited entries in the order the DACL holds them (nearest ancestor first,
  each level's denies before its allows).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# A change here changes what a scan concludes about a file, so incremental reuse must
# not replay an older verdict: this is part of the engine's version signature.
ACL_ANALYSIS_VERSION = "acl-3"

# Well-known SIDs of groups every (or nearly every) user is in.
BROAD_SIDS = {
    "S-1-1-0": "Everyone",
    "S-1-5-7": "Anonymous Logon",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-2": "Network",
    "S-1-5-4": "Interactive",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
}
# Domain-relative RIDs: S-1-5-21-<domain>-<rid>.
BROAD_DOMAIN_RIDS = {"501": "Guest", "513": "Domain Users", "514": "Domain Guests", "515": "Domain Computers"}
BROAD_NAMES = {"everyone", "anonymous logon", "authenticated users", "network", "interactive", "users", "guests",
               "guest", "domain users", "domain guests", "domain computers"}

PRIVILEGED_SIDS = {"S-1-5-18": "SYSTEM", "S-1-5-32-544": "Administrators"}
PRIVILEGED_DOMAIN_RIDS = {"500": "Administrator", "512": "Domain Admins", "518": "Schema Admins",
                          "519": "Enterprise Admins"}
PRIVILEGED_NAMES = {"system", "administrators", "administrator", "domain admins", "schema admins", "enterprise admins"}

# Service identities: a process, not a person. IUSR, IIS_IUSRS, LOCAL/NETWORK SERVICE,
# and every virtual NT SERVICE\<name> / IIS APPPOOL\<name> account.
SERVICE_SIDS = {"S-1-5-17": "IUSR", "S-1-5-19": "Local Service", "S-1-5-20": "Network Service",
                "S-1-5-32-568": "IIS_IUSRS"}
SERVICE_SID_PREFIXES = ("S-1-5-80-", "S-1-5-82-")
SERVICE_NAMES = {"iusr", "iis_iusrs", "local service", "network service"}
SERVICE_DOMAINS = {"nt service", "iis apppool"}

# Access-mask bits (winnt.h). Generic rights appear on inherited-only entries and on
# some copied ACLs.
_FILE_READ_DATA = 0x1
_FILE_WRITE_DATA = 0x2
_FILE_APPEND_DATA = 0x4
_WRITE_DAC = 0x40000
_WRITE_OWNER = 0x80000
_GENERIC_ALL = 0x10000000
_GENERIC_EXECUTE = 0x20000000
_GENERIC_WRITE = 0x40000000
_GENERIC_READ = 0x80000000
# What each generic right stands for on a file (FILE_GENERIC_READ and the rest), so an
# allow written in generic rights and a deny written in file rights meet bit for bit.
_GENERIC_MAP = ((_GENERIC_READ, 0x120089), (_GENERIC_WRITE, 0x120116), (_GENERIC_EXECUTE, 0x1200A0),
                (_GENERIC_ALL, 0x1F01FF))
# The rights that make a verdict. Reading is reading the data. Writing is writing or
# appending it - or changing the permissions or the owner, since either lets the holder
# grant itself write. Delete, attributes and extended attributes alone change no content,
# so a deny of one of them leaves "can write" standing.
_READ = _FILE_READ_DATA
_WRITE = _FILE_WRITE_DATA | _FILE_APPEND_DATA | _WRITE_DAC | _WRITE_OWNER
# Rights names as .NET renders them (Get-Acl, and rights_to_names), with their masks.
_RIGHT_NAMES = {
    "readdata": 0x1, "listdirectory": 0x1, "writedata": 0x2, "createfiles": 0x2, "appenddata": 0x4,
    "createdirectories": 0x4, "readextendedattributes": 0x8, "writeextendedattributes": 0x10,
    "executefile": 0x20, "traverse": 0x20, "deletesubdirectoriesandfiles": 0x40, "readattributes": 0x80,
    "writeattributes": 0x100, "write": 0x116, "delete": 0x10000, "readpermissions": 0x20000,
    "read": 0x20089, "readandexecute": 0x200A9, "modify": 0x301BF, "changepermissions": _WRITE_DAC,
    "takeownership": _WRITE_OWNER, "synchronize": 0x100000, "fullcontrol": 0x1F01FF,
}


def indexer_principals() -> set[str]:
    """Accounts an operator names as indexers or crawlers (DSPM_INDEXER_PRINCIPALS,
    comma-separated, DOMAIN\\name or name), matched exactly and case-insensitively."""
    raw = os.getenv("DSPM_INDEXER_PRINCIPALS", "")
    return {item.strip().lower() for item in raw.split(",") if item.strip()}


@dataclass
class Access:
    """One principal's effective access to one file."""
    principal: str
    sid: str
    key: str
    read: bool
    write: bool
    broad: bool
    privileged: bool
    service: bool

    def row(self) -> dict:
        return {"principal": self.principal, "sid": self.sid, "key": self.key, "read": self.read,
                "write": self.write, "broad": self.broad, "privileged": self.privileged, "service": self.service}


def _account(name: str) -> tuple[str, str]:
    """(domain, account), lower-cased."""
    text = str(name or "").strip().lower()
    if "\\" in text:
        domain, account = text.split("\\", 1)
        return domain, account
    return "", text


def _domain_rid(sid: str) -> str:
    return sid.rsplit("-", 1)[-1] if sid.upper().startswith("S-1-5-21-") else ""


def principal_key(principal: str, sid: str) -> str:
    """How the same principal is recognised across files: its SID when known."""
    return sid.upper() if sid else str(principal or "").strip().lower()


def classify_principal(principal: str, sid: str = "") -> tuple[bool, bool, bool]:
    """(broad, privileged, service) for one principal."""
    sid = str(sid or "").strip().upper()
    domain, account = _account(principal)
    rid = _domain_rid(sid)
    broad = sid in BROAD_SIDS or rid in BROAD_DOMAIN_RIDS or (not sid and account in BROAD_NAMES)
    privileged = sid in PRIVILEGED_SIDS or rid in PRIVILEGED_DOMAIN_RIDS or (not sid and account in PRIVILEGED_NAMES)
    indexers = indexer_principals()
    service = (sid in SERVICE_SIDS or sid.startswith(SERVICE_SID_PREFIXES) or domain in SERVICE_DOMAINS
               or account in SERVICE_NAMES or str(principal or "").strip().lower() in indexers
               or account in indexers)
    return broad, privileged, service


def _mask(entry: dict) -> int:
    """One entry's access mask - recorded, or built from its rights names (Get-Acl renders
    bits it has no name for, generic rights among them, as a number) - with each generic
    right replaced by the file rights it stands for."""
    mask = entry.get("mask")
    if not (isinstance(mask, int) and not isinstance(mask, bool) and mask):
        mask = 0
        for part in str(entry.get("rights") or "").split(","):
            name = part.strip().replace(" ", "").lower()
            mask |= (int(name) & 0xFFFFFFFF) if name.lstrip("-").isdigit() else _RIGHT_NAMES.get(name, 0)
    mask &= 0xFFFFFFFF
    for generic, specific in _GENERIC_MAP:
        if mask & generic:
            mask = (mask & ~generic) | specific
    return mask


def _is_deny(entry: dict) -> bool:
    return str(entry.get("type") or "allow").lower().startswith("deny")


def _evaluation_order(entries: list[dict]) -> list[dict]:
    """Windows' canonical order: explicit denies, explicit allows, then the inherited
    entries as the DACL holds them. Within the inherited ones the recorded order is kept:
    the DACL lists the nearest ancestor's entries first, each level's denies before its
    allows, and a nearer level's allow outranks a farther level's deny. An entry that
    does not say whether it was inherited (older records, Get-Acl) counts as explicit."""
    explicit = [entry for entry in entries if not entry.get("inherited")]
    inherited = [entry for entry in entries if entry.get("inherited")]
    return ([entry for entry in explicit if _is_deny(entry)] + [entry for entry in explicit if not _is_deny(entry)]
            + inherited)


def entries_of(acl: dict) -> list[dict]:
    """The ACL's entries - or, for a collector that recorded only the parallel lists,
    one allow entry per principal (what those lists always meant)."""
    entries = acl.get("entries")
    if isinstance(entries, list) and entries:
        return [entry for entry in entries if isinstance(entry, dict)]
    principals = list(acl.get("principals") or [])
    permissions = list(acl.get("permissions") or [])
    types = list(acl.get("types") or [])
    return [{"principal": str(principal), "sid": "", "rights": str(permissions[index]) if index < len(permissions) else "",
             "type": str(types[index]).lower() if index < len(types) else "allow"}
            for index, principal in enumerate(principals)]


def effective_access(acl: dict) -> list[Access]:
    """Each principal's effective read and write; principals with neither are left out.

    Evaluated as Windows evaluates a DACL for one principal: walking the entries in
    canonical order, each right (mask bit) is decided by the first entry that names it -
    granted by an allow, refused by a deny - and what was granted is the access. A deny
    therefore takes only the rights it names, and only from allows it comes before."""
    names: dict[str, tuple[str, str]] = {}
    keyed: list[dict] = []
    for entry in entries_of(acl or {}):
        principal = str(entry.get("principal") or "").strip()
        sid = str(entry.get("sid") or "").strip()
        if not principal and not sid:
            continue
        key = principal_key(principal, sid)
        names.setdefault(key, (principal or sid, sid))
        keyed.append({**entry, "_key": key})
    granted: dict[str, int] = {}
    decided: dict[str, int] = {}
    for entry in _evaluation_order(keyed):
        key = entry["_key"]
        undecided = _mask(entry) & ~decided.get(key, 0)
        decided[key] = decided.get(key, 0) | undecided
        if not _is_deny(entry):
            granted[key] = granted.get(key, 0) | undecided
    result: list[Access] = []
    for key, (principal, sid) in names.items():
        rights = granted.get(key, 0)
        can_read, can_write = bool(rights & _READ), bool(rights & _WRITE)
        if not (can_read or can_write):
            continue
        broad, privileged, service = classify_principal(principal, sid)
        result.append(Access(principal, sid, key, can_read, can_write, broad, privileged, service))
    return result


def analyze_acl(acl: dict, file_record: dict | None = None) -> dict:
    access = effective_access(acl or {})
    wide_access = any(item.broad and item.read for item in access)
    writable = any(item.broad and item.write for item in access)
    privileged_access = any(item.privileged for item in access)
    service_readers = sorted({item.principal for item in access if item.service and item.read})
    broad_readers = sorted({item.principal for item in access if item.broad and item.read})

    issues: list[str] = []
    if wide_access:
        issues.append("Broad group access detected")
    if writable:
        issues.append("Broad writable access detected")
    if service_readers:
        issues.append("Service or indexer accounts can read this file")
    if not acl:
        issues.append("ACL data was not available during this scan")

    score = 0
    if wide_access:
        score += 20
    if writable:
        score += 15
    if privileged_access and not wide_access:
        score += 5

    return {
        "score": min(score, 40),
        "wide_access": wide_access,
        "writable": writable,
        "privileged_access": privileged_access,
        "broad_readers": broad_readers,
        "service_readers": service_readers,
        "issues": issues,
        "analysis_version": ACL_ANALYSIS_VERSION,
    }
