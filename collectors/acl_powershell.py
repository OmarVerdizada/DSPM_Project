"""One reading of a Windows security descriptor in PowerShell, for every collector that
reads ACLs through PowerShell: the WinRM endpoint script, and the SMB collector's batched
and per-file fallbacks.

Each used to render the ACL its own way - ``Get-Acl`` and ``.Access``, the rights as
``FileSystemRights.ToString()`` - and between them they lost the owner's SID, the access
mask, the inheritance flags and whether the DACL is protected; the SMB paths lost the SIDs
and the inherited flag too, so a broad group was known only by its English name. They now
share ``ConvertTo-DspmAclFields`` below, and ``acl_from_fields`` turns what it sends into
the ``acl`` dict every collector produces (see ``permissions.acl_analyzer``).

What it sends per file: the owner's name and SID; per entry the principal's name and SID,
the access mask as a number, allow or deny, inherited, and the inheritance and propagation
flags (``aflags``: inheritance + 4 * propagation, both as .NET numbers them); whether the
DACL is protected (inheritance disabled); ``acl_state``/``acl_error``; and ``lookups`` -
how many SIDs it asked an authority to name for this file (``acl_read_stats`` sums them).

Cost (MEASURED, 3,000 local files, this host): ``Get-Acl`` with ``.Owner`` and ``.Access``
took 1.55 ms a file; ``FileInfo.GetAccessControl`` for the owner and the DACL, the rules
read once by SID and each SID translated to a name once per command, 0.14-0.18 ms - and it
sends more. A SID no authority can name is sent as the SID itself: the principal is then
an unresolved SID, never dropped.
"""

from __future__ import annotations

from permissions.acl_analyzer import ace_flags

# Defines the SID-name cache and the conversion. ``$dspmSidNames`` lives in the scope that
# dot-sources this - one per command, one per runspace of a pool - and is only ever
# mutated, never reassigned, so a function can fill it.
ACL_FIELDS_PS = r"""
$dspmSidNames = @{}
function Get-DspmAclErrorName($dspmError) {
  $dspmException = $dspmError.Exception
  while ($dspmException -and $dspmException.InnerException -and
         ($dspmException -is [System.Management.Automation.MethodInvocationException] -or
          $dspmException -is [System.Management.Automation.RuntimeException])) {
    $dspmException = $dspmException.InnerException
  }
  if ($dspmException -is [System.UnauthorizedAccessException]) { return "access_denied" }
  if ($dspmException -is [System.IO.FileNotFoundException] -or $dspmException -is [System.IO.DirectoryNotFoundException] -or
      $dspmException -is [System.Management.Automation.ItemNotFoundException]) { return "not_found" }
  if ($dspmException -is [System.IO.PathTooLongException]) { return "path_too_long" }
  if ($dspmException) { return [string]$dspmException.GetType().Name }
  return "error"
}
function ConvertTo-DspmAclFields($dspmSd, $dspmWithAccess) {
  $dspmFields = [ordered]@{
    acl_state = "collected"; owner = ""; owner_sid = ""; acl_protected = $null
    principals = @(); sids = @(); masks = @(); types = @(); inherited = @(); aflags = @(); lookups = 0
  }
  $dspmLookups = 0
  try {
    $dspmOwnerSid = [string]$dspmSd.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  } catch {
    $dspmOwnerSid = ""
  }
  if ($dspmOwnerSid) {
    $dspmName = $dspmSidNames[$dspmOwnerSid]
    if ($null -eq $dspmName) {
      $dspmLookups++
      try {
        $dspmName = ([System.Security.Principal.SecurityIdentifier]$dspmOwnerSid).Translate([System.Security.Principal.NTAccount]).Value
      } catch {
        $dspmName = $dspmOwnerSid
      }
      $dspmSidNames[$dspmOwnerSid] = $dspmName
    }
    $dspmFields.owner = $dspmName
    $dspmFields.owner_sid = $dspmOwnerSid
  }
  if ($dspmWithAccess) {
    $dspmFields.acl_protected = [bool]$dspmSd.AreAccessRulesProtected
    $dspmRules = @($dspmSd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
    $dspmFields.sids = @(foreach ($dspmRule in $dspmRules) { $dspmRule.IdentityReference.Value })
    $dspmFields.principals = @(foreach ($dspmSid in $dspmFields.sids) {
      $dspmName = $dspmSidNames[$dspmSid]
      if ($null -eq $dspmName) {
        $dspmLookups++
        try {
          $dspmName = ([System.Security.Principal.SecurityIdentifier]$dspmSid).Translate([System.Security.Principal.NTAccount]).Value
        } catch {
          $dspmName = $dspmSid
        }
        $dspmSidNames[$dspmSid] = $dspmName
      }
      $dspmName
    })
    $dspmFields.masks = @(foreach ($dspmRule in $dspmRules) { [int]$dspmRule.FileSystemRights })
    $dspmFields.types = @(foreach ($dspmRule in $dspmRules) { $dspmRule.AccessControlType.ToString() })
    $dspmFields.inherited = @(foreach ($dspmRule in $dspmRules) { [bool]$dspmRule.IsInherited })
    $dspmFields.aflags = @(foreach ($dspmRule in $dspmRules) { [int]$dspmRule.InheritanceFlags + 4 * [int]$dspmRule.PropagationFlags })
  }
  # How many SIDs this file sent to an authority to be named: the cache makes it one a SID
  # a command (a runspace), not one an entry.
  $dspmFields.lookups = $dspmLookups
  return $dspmFields
}
"""


def _listed(value) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def acl_read_stats(fields_list) -> dict:
    """What reading the ACLs cost, from what the script sent: files whose ACL it read,
    reads that failed, SIDs sent to an authority to be named, and entries read."""
    reads = failed = lookups = entries = 0
    for fields in fields_list:
        if not isinstance(fields, dict):
            continue
        reads += 1
        if str(fields.get("acl_state") or "") == "failed":
            failed += 1
        lookups += _int(fields.get("lookups"))
        entries += len(_listed(fields.get("sids")))
    return {"reads": reads, "failed": failed, "sid_lookups": lookups, "entries": entries}


def acl_from_fields(row: dict, *, with_access: bool = True) -> dict:
    """The ``acl`` dict from what ``ConvertTo-DspmAclFields`` sent (and ``acl_state`` /
    ``acl_error`` the caller set when the read failed). Rights names are rendered here, from
    the mask, exactly as .NET renders them - the parallel lists reports carry keep their
    wording, and the wire carries a number instead of a sentence."""
    from collectors.win_security import rights_to_names

    state = str(row.get("acl_state") or "collected").strip().lower()
    if state == "failed":
        return {"owner": "", "principals": [], "permissions": [], "state": "failed",
                "error": str(row.get("acl_error") or "error")[:120]}
    if state == "not_collected":
        return {"owner": "", "principals": [], "permissions": [], "state": "not_collected"}
    owner = str(row.get("owner") or "")
    acl: dict = {"owner": owner, "owner_sid": str(row.get("owner_sid") or "").upper(), "state": "collected"}
    if not with_access:
        acl.update({"principals": [], "permissions": []})
        return acl
    names, sids, masks = _listed(row.get("principals")), _listed(row.get("sids")), _listed(row.get("masks"))
    types, inherited, aflags = _listed(row.get("types")), _listed(row.get("inherited")), _listed(row.get("aflags"))
    entries: list[dict] = []
    for index, sid in enumerate(sids):
        sid_text = str(sid or "").strip().upper()
        name = str(names[index] or "") if index < len(names) else ""
        if not sid_text and not name:
            continue
        mask = _int(masks[index] if index < len(masks) else 0) & 0xFFFFFFFF
        packed = _int(aflags[index] if index < len(aflags) else 0)
        is_inherited = bool(inherited[index]) if index < len(inherited) else False
        entry = {"principal": name or sid_text, "sid": sid_text, "rights": rights_to_names(mask), "mask": mask,
                 "type": "deny" if str(types[index] if index < len(types) else "Allow").lower().startswith("deny")
                 else "allow",
                 "inherited": is_inherited}
        entry["flags"] = ace_flags({"inheritance_flags": packed & 3, "propagation_flags": (packed >> 2) & 3,
                                    "inherited": is_inherited})
        if entry["flags"] & 0x8:
            entry["inherit_only"] = True
        entries.append(entry)
    acl["principals"] = [entry["principal"] for entry in entries]
    acl["permissions"] = [entry["rights"] for entry in entries]
    acl["types"] = [entry["type"] for entry in entries]
    acl["entries"] = entries
    if row.get("acl_protected") is not None:
        acl["protected"] = bool(row.get("acl_protected"))
    return acl
