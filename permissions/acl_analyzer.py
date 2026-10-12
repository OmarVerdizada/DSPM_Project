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

What the access model (revision 0055) added, and why:

* The access is **direct ACL access**: what the entries naming a principal grant it, less
  what the entries naming the same principal deny. Group membership is not expanded -
  nested AD groups are not resolved - so a user's access through the groups it belongs to
  is not shown as that user's, and a deny for a group does not reach its members here.
  Nothing in this module calls that "effective access"; the console says so.
* Every principal in the ACL is described, not only those who can read or write: a
  deny-only principal and the owner are rows too, with the rights each entry grants
  (read, read & execute, write, modify, full control, delete, change permissions, take
  ownership), whether they came from explicit or inherited entries, and the principal's
  type as the collector resolved it (user, group, computer, service identity, unresolved
  SID) - or, where it could not, as the SID's own structure proves it, else "unknown".
* An inherit-only entry does not apply to the object it is on; it was evaluated as if it
  did.
* A collector that could not read the ACL says so (``state: failed``, ``error``): "no
  permissions" and "permissions not read" are different answers.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# A change here changes what a scan concludes about a file, so incremental reuse must
# not replay an older verdict: this is part of the engine's version signature.
ACL_ANALYSIS_VERSION = "acl-3"
# The access model below (principal rows, rights, owner, state, the access findings) is
# derived from the record's ACL alone - never from its content - so a replayed record is
# re-derived when this differs, without reading the file again.
ACCESS_MODEL_VERSION = "access-1"

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
        if _inherit_only(entry):
            continue  # it applies to the folder's children, not to the object it is on
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
    state = acl_state(acl or {})
    if state == "failed":
        issues.append(f"ACL could not be read during this scan ({str((acl or {}).get('error') or 'error')})")
    elif state == "not_collected":
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
        "acl_state": state,
        "analysis_version": ACL_ANALYSIS_VERSION,
        "access_model_version": ACCESS_MODEL_VERSION,
    }


# --- the access model (revision 0055) ----------------------------------------------------

PRINCIPAL_TYPES = ("user", "group", "well_known_group", "computer", "service", "unresolved_sid", "unknown")
# LookupAccountSid's SID_NAME_USE, as a principal type. A deleted account (6) and a SID no
# authority could name (7 invalid, 8 unknown) are both unresolved: who they were is unknown.
SID_NAME_USE_TYPES = {1: "user", 2: "group", 4: "group", 5: "well_known_group", 6: "unresolved_sid",
                      7: "unresolved_sid", 8: "unresolved_sid", 9: "computer", 11: "well_known_group"}
# Well-known groups (winnt.h, MS-DTYP 2.4.2.4): what the SID proves without a lookup.
WELL_KNOWN_GROUP_SIDS = frozenset({
    "S-1-1-0", "S-1-2-0", "S-1-2-1", "S-1-3-0", "S-1-3-1", "S-1-3-4", "S-1-5-1", "S-1-5-2", "S-1-5-3",
    "S-1-5-4", "S-1-5-6", "S-1-5-7", "S-1-5-8", "S-1-5-9", "S-1-5-10", "S-1-5-11", "S-1-5-12", "S-1-5-13",
    "S-1-5-14", "S-1-5-15", "S-1-5-1000", "S-1-5-113", "S-1-5-114", "S-1-15-2-1", "S-1-15-2-2",
})
# Service identities: LocalSystem, Local/Network Service, IUSR and the virtual accounts
# (NT SERVICE, IIS APPPOOL, virtual machines, window manager, font driver host).
SERVICE_IDENTITY_SIDS = frozenset({"S-1-5-17", "S-1-5-18", "S-1-5-19", "S-1-5-20"})
SERVICE_IDENTITY_PREFIXES = ("S-1-5-80-", "S-1-5-82-", "S-1-5-83-", "S-1-5-90-", "S-1-5-96-")
# Relative IDs whose kind is fixed in every domain and on every machine (MS-DTYP 2.4.2.4).
FIXED_USER_RIDS = frozenset({"500", "501", "502", "503", "504"})
FIXED_GROUP_RIDS = frozenset({str(rid) for rid in range(512, 528)} | {"553", "571", "572"})

_DELETE = 0x10000
_EXECUTE = 0x20
_FULL_CONTROL_BITS = 0x0F01FF  # every file right but SYNCHRONIZE, which grants nothing on its own
_DATA_WRITE = _FILE_WRITE_DATA | _FILE_APPEND_DATA
# ACE header flags (winnt.h). Collectors record them raw ("flags"); the .NET inheritance and
# propagation flags are translated to them.
ACE_OBJECT_INHERIT = 0x1
ACE_CONTAINER_INHERIT = 0x2
ACE_NO_PROPAGATE = 0x4
ACE_INHERIT_ONLY = 0x8
ACE_INHERITED = 0x10
# Levels of access, weakest first: what a row's rights add up to.
ACCESS_LEVELS = ("none", "special", "read", "write", "modify", "full_control")
ACL_STATES = ("collected", "failed", "not_collected")


def _looks_like_sid(value: str) -> bool:
    return str(value or "").strip().upper().startswith("S-1-")


def principal_type(principal: str, sid: str = "", resolved: str = "") -> str:
    """What kind of principal this is: the collector's own lookup (``resolved``, from
    SID_NAME_USE) when it made one, else only what the SID's structure or the account's
    authority proves; "unknown" otherwise - a user and a group look alike without a lookup.
    A service identity is that whatever the lookup called it (LookupAccountSid names
    SYSTEM and the NT SERVICE accounts well-known groups)."""
    sid = str(sid or "").strip().upper()
    name = str(principal or "").strip()
    if not sid and _looks_like_sid(name):
        sid = name.upper()
    domain, account = _account(name)
    if sid in SERVICE_IDENTITY_SIDS or sid.startswith(SERVICE_IDENTITY_PREFIXES) or domain in SERVICE_DOMAINS:
        return "service"
    resolved = str(resolved or "").strip().lower()
    if resolved in PRINCIPAL_TYPES and resolved != "unknown":
        return resolved
    if sid and (not name or _looks_like_sid(name)):
        return "unresolved_sid"  # no authority gave it a name
    if sid in WELL_KNOWN_GROUP_SIDS:
        return "well_known_group"
    if sid.startswith("S-1-5-32-"):
        return "group"  # BUILTIN aliases
    rid = _domain_rid(sid)
    if rid in FIXED_USER_RIDS:
        return "user"
    if rid in FIXED_GROUP_RIDS:
        return "group"
    if domain == "builtin":
        return "group"
    if domain == "nt authority":
        return "well_known_group"
    if account.endswith("$"):
        return "computer"
    return "unknown"


def ace_flags(entry: dict) -> int:
    """An entry's ACE header flags: recorded raw, or rebuilt from the .NET inheritance
    (ContainerInherit 1, ObjectInherit 2) and propagation (NoPropagateInherit 1,
    InheritOnly 2) flags, with the inherited bit."""
    raw = entry.get("flags")
    if isinstance(raw, int) and not isinstance(raw, bool):
        flags = raw & 0xFF
    else:
        inheritance = int(entry.get("inheritance_flags") or 0)
        propagation = int(entry.get("propagation_flags") or 0)
        flags = ((ACE_CONTAINER_INHERIT if inheritance & 1 else 0) | (ACE_OBJECT_INHERIT if inheritance & 2 else 0)
                 | (ACE_NO_PROPAGATE if propagation & 1 else 0) | (ACE_INHERIT_ONLY if propagation & 2 else 0))
    if entry.get("inherited"):
        flags |= ACE_INHERITED
    return flags


def _inherit_only(entry: dict) -> bool:
    return bool(entry.get("inherit_only")) or bool(ace_flags(entry) & ACE_INHERIT_ONLY)


def applies_to(entry: dict, *, container: bool = False) -> str:
    """Where an entry applies, in the words of the Advanced Security dialog."""
    flags = ace_flags(entry)
    if flags & ACE_INHERIT_ONLY:
        return "Child objects only - not this " + ("folder" if container else "file")
    if not container:
        return "This file"
    children = []
    if flags & ACE_CONTAINER_INHERIT:
        children.append("subfolders")
    if flags & ACE_OBJECT_INHERIT:
        children.append("files")
    if not children:
        return "This folder only"
    scope = "This folder, " + " and ".join(children)
    return scope + (" (one level)" if flags & ACE_NO_PROPAGATE else "")


def rights_of(mask: int) -> dict[str, bool]:
    """The rights a mask grants, as the console names them."""
    mask = int(mask or 0) & 0xFFFFFFFF
    return {
        "read": bool(mask & _FILE_READ_DATA),
        "read_execute": (mask & (_FILE_READ_DATA | _EXECUTE)) == (_FILE_READ_DATA | _EXECUTE),
        "write": bool(mask & _DATA_WRITE),
        "modify": bool(mask & _DATA_WRITE) and bool(mask & _DELETE),
        "full_control": (mask & _FULL_CONTROL_BITS) == _FULL_CONTROL_BITS,
        "delete": bool(mask & _DELETE),
        "change_permissions": bool(mask & _WRITE_DAC),
        "take_ownership": bool(mask & _WRITE_OWNER),
    }


def access_level(mask: int) -> str:
    """The strongest level a mask amounts to (``ACCESS_LEVELS``). Changing the permissions
    or the owner counts as write: either lets the holder grant itself write."""
    rights = rights_of(mask)
    if rights["full_control"]:
        return "full_control"
    if rights["modify"]:
        return "modify"
    if rights["write"] or rights["change_permissions"] or rights["take_ownership"]:
        return "write"
    if rights["read"]:
        return "read"
    return "special" if int(mask or 0) & 0xFFFFFFFF else "none"


def rights_label(mask: int) -> str:
    """A mask in the words of the Security tab: "Full control", "Modify", "Read & execute,
    Write", ... - "Special" for rights none of those names (attributes, synchronize)."""
    mask = int(mask or 0) & 0xFFFFFFFF
    if not mask:
        return "None"
    rights = rights_of(mask)
    if rights["full_control"]:
        return "Full control"
    parts: list[str] = []
    if rights["modify"]:
        parts.append("Modify" if rights["read"] else "Modify (without Read)")
    else:
        if rights["read_execute"]:
            parts.append("Read & execute")
        elif rights["read"]:
            parts.append("Read")
        if rights["write"]:
            parts.append("Write")
        if rights["delete"]:
            parts.append("Delete")
    if rights["change_permissions"]:
        parts.append("Change permissions")
    if rights["take_ownership"]:
        parts.append("Take ownership")
    return ", ".join(parts) if parts else "Special"


def acl_state(acl: dict) -> str:
    """Whether the ACL was read: "collected", "failed" (the collector tried and could not -
    ``error`` says why) or "not_collected" (nothing was read: permissions were off, or an
    older record). A record without the field is judged by what it holds."""
    acl = acl if isinstance(acl, dict) else {}
    state = str(acl.get("state") or "").strip().lower()
    if state in ACL_STATES:
        return state
    if acl.get("error"):
        return "failed"
    if acl.get("owner") or acl.get("principals") or acl.get("entries"):
        return "collected"
    return "not_collected"


def owner_of(acl: dict) -> dict:
    """The owner as collected: its name, SID, type, and whether a name was resolved."""
    acl = acl if isinstance(acl, dict) else {}
    name = str(acl.get("owner") or "").strip()
    sid = str(acl.get("owner_sid") or "").strip().upper()
    if not sid and _looks_like_sid(name):
        sid = name.upper()
    if not name and not sid:
        return {"name": "", "sid": "", "type": "", "resolved": False, "key": "", "broad": False,
                "privileged": False, "service": False}
    kind = principal_type(name, sid, str(acl.get("owner_type") or ""))
    resolved = bool(name) and not _looks_like_sid(name)
    broad, privileged, service = classify_principal(name if resolved else "", sid)
    return {"name": name or sid, "sid": sid, "type": kind, "resolved": resolved, "key": principal_key(name, sid),
            "broad": broad, "privileged": privileged, "service": service}


@dataclass
class PrincipalAccess:
    """One principal's direct ACL access to one object: what the entries naming it grant,
    less what the entries naming it deny - group membership not expanded."""
    key: str
    principal: str
    sid: str
    principal_type: str
    granted: int = 0
    denied: int = 0
    explicit_granted: int = 0
    inherited_granted: int = 0
    explicit: bool = False
    inherited: bool = False
    is_owner: bool = False
    broad: bool = False
    privileged: bool = False
    service: bool = False

    @property
    def unresolved(self) -> bool:
        return self.principal_type == "unresolved_sid"

    @property
    def read(self) -> bool:
        return bool(self.granted & _READ)

    @property
    def write(self) -> bool:
        # The D7 verdict: writing the data, or changing the permissions or the owner -
        # either lets the holder grant itself write.
        return bool(self.granted & _WRITE)

    @property
    def modify(self) -> bool:
        return rights_of(self.granted)["modify"]

    @property
    def full_control(self) -> bool:
        return rights_of(self.granted)["full_control"]

    @property
    def change_permissions(self) -> bool:
        return bool(self.granted & (_WRITE_DAC | _WRITE_OWNER))

    @property
    def has_deny(self) -> bool:
        return bool(self.denied)

    @property
    def level(self) -> str:
        return access_level(self.granted)

    @property
    def rights(self) -> str:
        return rights_label(self.granted)

    @property
    def granted_by(self) -> str:
        explicit, inherited = bool(self.explicit_granted), bool(self.inherited_granted)
        if explicit and inherited:
            return "explicit and inherited"
        if explicit:
            return "explicit"
        if inherited:
            return "inherited"
        return ""

    def row(self) -> dict:
        return {
            "key": self.key, "principal": self.principal, "sid": self.sid, "principal_type": self.principal_type,
            "rights": self.rights, "level": self.level, "rights_detail": rights_of(self.granted),
            "allow_mask": self.granted, "deny_mask": self.denied,
            "denied_rights": rights_label(self.denied) if self.denied else "",
            "read": self.read, "write": self.write, "modify": self.modify, "full_control": self.full_control,
            "change_permissions": self.change_permissions, "has_deny": self.has_deny,
            "explicit": self.explicit, "inherited": self.inherited, "granted_by": self.granted_by,
            "explicit_rights": rights_label(self.explicit_granted) if self.explicit_granted else "",
            "inherited_rights": rights_label(self.inherited_granted) if self.inherited_granted else "",
            "is_owner": self.is_owner, "broad": self.broad, "privileged": self.privileged, "service": self.service,
            "unresolved": self.unresolved,
        }


def principal_access(acl: dict) -> list[PrincipalAccess]:
    """Every principal the ACL names - and the owner - with its direct access.

    Evaluated as ``effective_access`` evaluates (canonical order, bit by bit, inherit-only
    entries skipped), and kept whatever it amounts to: a principal whose entries only deny
    is a row (``has_deny``), so is an owner no entry names. Which rights an explicit entry
    granted and which an inherited one did is kept apart, so remediation can say whether
    removing an entry here would change anything (an inherited one comes back from the
    parent)."""
    acl = acl if isinstance(acl, dict) else {}
    found: dict[str, PrincipalAccess] = {}
    keyed: list[dict] = []
    for entry in entries_of(acl):
        principal = str(entry.get("principal") or "").strip()
        sid = str(entry.get("sid") or "").strip().upper()
        if not principal and not sid:
            continue
        if _inherit_only(entry):
            continue
        key = principal_key(principal, sid)
        if key not in found:
            broad, privileged, service = classify_principal(principal, sid)
            found[key] = PrincipalAccess(key, principal or sid, sid,
                                         principal_type(principal, sid, str(entry.get("principal_type") or "")),
                                         broad=broad, privileged=privileged, service=service)
        access = found[key]
        if entry.get("inherited"):
            access.inherited = True
        else:
            access.explicit = True
        if _is_deny(entry):
            access.denied |= _mask(entry)
        keyed.append({**entry, "_key": key})
    decided: dict[str, int] = {}
    for entry in _evaluation_order(keyed):
        access = found[entry["_key"]]
        undecided = _mask(entry) & ~decided.get(access.key, 0)
        decided[access.key] = decided.get(access.key, 0) | undecided
        if _is_deny(entry):
            continue
        access.granted |= undecided
        if entry.get("inherited"):
            access.inherited_granted |= undecided
        else:
            access.explicit_granted |= undecided
    owner = owner_of(acl)
    if owner["key"]:
        if owner["key"] not in found:
            name = owner["name"] if owner["resolved"] else owner["sid"]
            found[owner["key"]] = PrincipalAccess(owner["key"], name, owner["sid"], owner["type"],
                                                  broad=owner["broad"], privileged=owner["privileged"],
                                                  service=owner["service"])
        found[owner["key"]].is_owner = True
    return list(found.values())


def acl_entries(acl: dict, *, container: bool = False) -> list[dict]:
    """The entries as the console lists them, in the order the ACL holds them."""
    rows: list[dict] = []
    for index, entry in enumerate(entries_of(acl if isinstance(acl, dict) else {})):
        principal = str(entry.get("principal") or "").strip()
        sid = str(entry.get("sid") or "").strip().upper()
        if not principal and not sid:
            continue
        mask = _mask(entry)
        broad, privileged, service = classify_principal(principal, sid)
        kind = principal_type(principal, sid, str(entry.get("principal_type") or ""))
        rows.append({
            "ordinal": index, "principal": principal or sid, "sid": sid, "principal_type": kind,
            "access": "deny" if _is_deny(entry) else "allow", "rights": rights_label(mask),
            "rights_detail": rights_of(mask), "level": access_level(mask), "mask": mask,
            "raw_rights": str(entry.get("rights") or ""), "inherited": bool(entry.get("inherited")),
            "inherit_only": _inherit_only(entry), "flags": ace_flags(entry),
            "applies_to": applies_to(entry, container=container),
            "broad": broad, "privileged": privileged, "service": service,
            "unresolved": kind == "unresolved_sid", "null_dacl": bool(entry.get("null_dacl")),
        })
    return rows
