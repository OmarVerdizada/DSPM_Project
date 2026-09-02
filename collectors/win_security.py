"""In-process Windows security-descriptor reads.

Owner/ACL resolution used to spawn one ``powershell.exe`` per file. Measured on
this codebase that was **91% of total scan time**: 143 s of a 157 s local scan
(362 files), and roughly 11 of the 13 minutes of a 421-file SMB scan, while all
content classification together cost 0.9 s. Win32 exposes the same data in
microseconds, and ``GetNamedSecurityInfoW`` accepts UNC paths, so one
implementation serves both the local and the SMB collector.

The output is deliberately identical to what the PowerShell path produced -
owner as ``DOMAIN\\Account``, the ``.Access`` principal list, and .NET
``FileSystemRights`` names - so reports, evidence, and baselines do not shift.

Everything degrades to "no answer" (empty string / empty dict) rather than
raising: a security descriptor we cannot read must never fail a scan.
"""

from __future__ import annotations

import platform
import threading
from typing import Any

IS_WINDOWS = platform.system().lower() == "windows"

# Win32 constants
_SE_FILE_OBJECT = 1
_OWNER_SECURITY_INFORMATION = 0x00000001
_DACL_SECURITY_INFORMATION = 0x00000004
_ERROR_SUCCESS = 0
_ACCESS_ALLOWED_ACE_TYPE = 0
_ACCESS_DENIED_ACE_TYPE = 1

# .NET System.Security.AccessControl.FileSystemRights, ascending by value.
# Enum.ToString() for a [Flags] enum walks these largest-first, subtracting and
# prepending, so the rendered string matches Get-Acl exactly.
_FILE_SYSTEM_RIGHTS: tuple[tuple[int, str], ...] = (
    (1, "ReadData"),
    (2, "CreateFiles"),
    (4, "AppendData"),
    (8, "ReadExtendedAttributes"),
    (16, "WriteExtendedAttributes"),
    (32, "ExecuteFile"),
    (64, "DeleteSubdirectoriesAndFiles"),
    (128, "ReadAttributes"),
    (256, "WriteAttributes"),
    (278, "Write"),
    (65536, "Delete"),
    (131072, "ReadPermissions"),
    (131209, "Read"),
    (131241, "ReadAndExecute"),
    (197055, "Modify"),
    (262144, "ChangePermissions"),
    (524288, "TakeOwnership"),
    (1048576, "Synchronize"),
    (2032127, "FullControl"),
)

_sid_name_cache: dict[str, str] = {}
_sid_name_lock = threading.Lock()

_advapi32: Any = None
_kernel32: Any = None
_ctypes: Any = None
_wintypes: Any = None
_init_lock = threading.Lock()
_init_done = False
_available = False


def _init() -> bool:
    """Bind the Win32 entry points once. Returns False on any non-Windows or
    unexpected environment, which makes every public helper a graceful no-op."""
    global _init_done, _available, _advapi32, _kernel32, _ctypes, _wintypes
    if _init_done:
        return _available
    with _init_lock:
        if _init_done:
            return _available
        _init_done = True
        if not IS_WINDOWS:
            _available = False
            return False
        try:
            import ctypes
            from ctypes import wintypes

            advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

            advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
            advapi32.GetNamedSecurityInfoW.argtypes = [
                wintypes.LPCWSTR,       # pObjectName
                ctypes.c_int,           # ObjectType
                wintypes.DWORD,         # SecurityInfo
                ctypes.POINTER(ctypes.c_void_p),  # ppsidOwner
                ctypes.POINTER(ctypes.c_void_p),  # ppsidGroup
                ctypes.POINTER(ctypes.c_void_p),  # ppDacl
                ctypes.POINTER(ctypes.c_void_p),  # ppSacl
                ctypes.POINTER(ctypes.c_void_p),  # ppSecurityDescriptor
            ]

            advapi32.LookupAccountSidW.restype = wintypes.BOOL
            advapi32.LookupAccountSidW.argtypes = [
                wintypes.LPCWSTR, ctypes.c_void_p,
                wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
                wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
                ctypes.POINTER(ctypes.c_int),
            ]

            advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
            advapi32.ConvertSidToStringSidW.argtypes = [
                ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)
            ]

            advapi32.GetAclInformation.restype = wintypes.BOOL
            advapi32.GetAclInformation.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_int
            ]

            advapi32.GetAce.restype = wintypes.BOOL
            advapi32.GetAce.argtypes = [
                ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)
            ]

            kernel32.LocalFree.restype = ctypes.c_void_p
            kernel32.LocalFree.argtypes = [ctypes.c_void_p]

            _ctypes = ctypes
            _wintypes = wintypes
            _advapi32 = advapi32
            _kernel32 = kernel32
            _available = True
        except Exception:
            _available = False
        return _available


def available() -> bool:
    """True when in-process security reads can be used on this host."""
    return _init()


def _sid_to_string(sid_ptr: Any) -> str:
    ctypes, wintypes = _ctypes, _wintypes
    buffer = wintypes.LPWSTR()
    if not _advapi32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(buffer)):
        return ""
    try:
        return str(buffer.value or "")
    finally:
        _kernel32.LocalFree(ctypes.cast(buffer, ctypes.c_void_p))


def _account_for_sid(sid_ptr: Any) -> str:
    """``DOMAIN\\Account`` for a SID, cached by SID string.

    The cache is the point: LookupAccountSidW round-trips to a domain
    controller for domain SIDs, and a scan sees the same handful of principals
    across thousands of files.
    """
    sid_string = _sid_to_string(sid_ptr)
    if sid_string:
        with _sid_name_lock:
            cached = _sid_name_cache.get(sid_string)
        if cached is not None:
            return cached

    ctypes, wintypes = _ctypes, _wintypes
    name_len = wintypes.DWORD(0)
    domain_len = wintypes.DWORD(0)
    use = ctypes.c_int(0)
    # First call sizes the buffers (expected to fail with ERROR_INSUFFICIENT_BUFFER).
    _advapi32.LookupAccountSidW(None, sid_ptr, None, ctypes.byref(name_len),
                                None, ctypes.byref(domain_len), ctypes.byref(use))
    resolved = ""
    if name_len.value:
        name = ctypes.create_unicode_buffer(name_len.value)
        domain = ctypes.create_unicode_buffer(max(1, domain_len.value))
        if _advapi32.LookupAccountSidW(None, sid_ptr, name, ctypes.byref(name_len),
                                       domain, ctypes.byref(domain_len), ctypes.byref(use)):
            account = str(name.value or "")
            domain_name = str(domain.value or "")
            resolved = f"{domain_name}\\{account}" if domain_name and account else account
    # An unresolvable SID still identifies the principal - Get-Acl renders the
    # SID string in exactly this case, so keep that behaviour.
    if not resolved:
        resolved = sid_string

    if sid_string:
        with _sid_name_lock:
            _sid_name_cache[sid_string] = resolved
    return resolved


def rights_to_names(mask: int) -> str:
    """Render an access mask the way .NET's FileSystemRights.ToString() does."""
    remaining = int(mask) & 0xFFFFFFFF
    if remaining == 0:
        return "0"
    parts: list[str] = []
    for value, name in reversed(_FILE_SYSTEM_RIGHTS):
        if value and (remaining & value) == value:
            remaining -= value
            parts.insert(0, name)
    if remaining:
        parts.insert(0, str(remaining))
    return ", ".join(parts) if parts else str(mask)


def _read_dacl(dacl_ptr: Any) -> tuple[list[str], list[str]]:
    """(principals, permissions) parallel lists, mirroring Get-Acl's .Access."""
    ctypes = _ctypes
    if not dacl_ptr:
        return [], []

    class ACL_SIZE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("AceCount", ctypes.c_ulong),
            ("AclBytesInUse", ctypes.c_ulong),
            ("AclBytesFree", ctypes.c_ulong),
        ]

    info = ACL_SIZE_INFORMATION()
    # AclSizeInformation == 2
    if not _advapi32.GetAclInformation(dacl_ptr, ctypes.byref(info),
                                       ctypes.sizeof(info), 2):
        return [], []

    principals: list[str] = []
    permissions: list[str] = []
    for index in range(int(info.AceCount)):
        ace_ptr = ctypes.c_void_p()
        if not _advapi32.GetAce(dacl_ptr, index, ctypes.byref(ace_ptr)):
            continue
        address = ace_ptr.value
        if not address:
            continue
        ace_type = ctypes.c_ubyte.from_address(address).value
        if ace_type not in (_ACCESS_ALLOWED_ACE_TYPE, _ACCESS_DENIED_ACE_TYPE):
            continue
        # ACCESS_ALLOWED_ACE: ACE_HEADER (4 bytes) + ACCESS_MASK (4) + SidStart
        mask = ctypes.c_ulong.from_address(address + 4).value
        sid_ptr = ctypes.c_void_p(address + 8)
        principals.append(_account_for_sid(sid_ptr))
        permissions.append(rights_to_names(mask))
    return principals, permissions


def security_for_path(path: str, *, with_dacl: bool = True) -> dict:
    """Owner (and optionally principals/permissions) for a local or UNC path.

    Returns ``{}`` when the descriptor cannot be read, so callers can fall back.
    """
    if not _init() or not path:
        return {}
    ctypes = _ctypes
    owner_sid = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    info = _OWNER_SECURITY_INFORMATION | (_DACL_SECURITY_INFORMATION if with_dacl else 0)
    try:
        status = _advapi32.GetNamedSecurityInfoW(
            str(path), _SE_FILE_OBJECT, info,
            ctypes.byref(owner_sid), None,
            ctypes.byref(dacl) if with_dacl else None, None,
            ctypes.byref(descriptor),
        )
    except Exception:
        return {}
    if status != _ERROR_SUCCESS or not descriptor.value:
        if descriptor.value:
            _kernel32.LocalFree(descriptor)
        return {}
    try:
        result: dict = {"owner": _account_for_sid(owner_sid) if owner_sid.value else ""}
        if with_dacl:
            principals, permissions = _read_dacl(dacl.value)
            result["principals"] = principals
            result["permissions"] = permissions
        return result
    except Exception:
        return {}
    finally:
        _kernel32.LocalFree(descriptor)


def owner_for_path(path: str) -> str:
    """Just the owner - skips DACL parsing when the caller needs nothing else."""
    return str(security_for_path(path, with_dacl=False).get("owner") or "")


def cache_stats() -> dict:
    with _sid_name_lock:
        return {"sid_cache_entries": len(_sid_name_cache)}
