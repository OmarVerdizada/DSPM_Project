"""Findings about who can reach a sensitive file - from its ACL, never from its content.

A file becomes an access finding only when it already holds sensitive data (a data
finding) AND its ACL, as collected, proves an exposure:

* ``access_broad_write`` - a broad group (Everyone, Authenticated Users, Users, Domain
  Users, Guests, Anonymous Logon, ...) can write, modify or fully control it, or change its
  permissions or owner;
* ``access_broad_read`` - a broad group can read it (and none can write it: then the write
  finding says both);
* ``access_owner_risk`` - its owner is a broad group or an unresolved SID: an owner can
  always read the permissions and change them, whatever the entries say;
* ``access_unresolved_sid`` - an entry grants access to a SID no authority could name (a
  deleted account, or one Sentro cannot query);
* ``access_service_read`` - a service identity (IUSR, IIS_IUSRS, Local/Network Service, an
  NT SERVICE account, an indexer named in DSPM_INDEXER_PRINCIPALS) can read it;
* ``access_excessive_principals`` - more principals than DSPM_ACCESS_MAX_PRINCIPALS hold
  direct read access.

At most one of each per file: the principals are listed inside it, so ten broad groups on
one file are one finding, not ten. Nothing is raised because an ACL exists, for a file
without sensitive data, or for an ACL that was not read - "not read" is said on the file,
not turned into a finding. The access is direct ACL access (``permissions.acl_analyzer``):
group membership is not expanded, and each finding says so.

Derived from the record's ACL and data findings alone, these are recomputed every time a
record is analyzed or replayed, so they follow the ACL a scan read - never an older one.
"""

from __future__ import annotations

import os

from permissions.acl_analyzer import (
    ACCESS_MODEL_VERSION,
    PrincipalAccess,
    acl_state,
    owner_of,
    principal_access,
    rights_label,
)

ACCESS_FINDING_TYPES = (
    "access_broad_write", "access_broad_read", "access_owner_risk", "access_unresolved_sid",
    "access_service_read", "access_excessive_principals",
)
ACCESS_CATEGORY = "access_exposure"
ACCESS_FINDING_CATEGORY = "Access Exposure"
DISPLAY_NAMES = {
    "access_broad_write": "Sensitive file writable by a broad group",
    "access_broad_read": "Sensitive file readable by a broad group",
    "access_owner_risk": "Sensitive file owned by a broad group or an unknown account",
    "access_unresolved_sid": "Sensitive file accessible to an unresolved SID",
    "access_service_read": "Sensitive file readable by a service identity",
    "access_excessive_principals": "Sensitive file with excessive direct access",
}
# Who anyone at all can be: the broad groups that include unauthenticated or guest logons.
ANONYMOUS_SIDS = frozenset({"S-1-1-0", "S-1-5-7", "S-1-5-32-546"})
ANONYMOUS_RIDS = frozenset({"501", "514"})
# Web-facing service identities: what they read, a web request can.
WEB_SERVICE_SIDS = frozenset({"S-1-5-17", "S-1-5-32-568"})
_SEVERITY_ORDER = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
MODEL_NOTE = ("The rights the file's own entries grant each principal. Group membership was not expanded, so "
              "members of these groups are not listed one by one.")


def enabled() -> bool:
    """``DSPM_ACCESS_FINDINGS`` (on): sensitive files exposed through their ACL are findings."""
    return os.getenv("DSPM_ACCESS_FINDINGS", "1").strip().lower() not in {"0", "false", "no", "off"}


def max_principals() -> int:
    try:
        return max(2, min(int(os.getenv("DSPM_ACCESS_MAX_PRINCIPALS", "25")), 10_000))
    except ValueError:
        return 25


def is_access_finding(finding: dict) -> bool:
    return isinstance(finding, dict) and (bool(finding.get("access_finding"))
                                          or str(finding.get("type") or "") in ACCESS_FINDING_TYPES)


def _anonymous(access: PrincipalAccess) -> bool:
    sid = access.sid.upper()
    return sid in ANONYMOUS_SIDS or (sid.startswith("S-1-5-21-") and sid.rsplit("-", 1)[-1] in ANONYMOUS_RIDS)


def _raise(severity: str, steps: int = 1) -> str:
    index = _SEVERITY_ORDER.index(severity) if severity in _SEVERITY_ORDER else 0
    return _SEVERITY_ORDER[min(len(_SEVERITY_ORDER) - 2, index + steps)]  # never CRITICAL from an ACL alone


def _sensitive_context(findings: list[dict], risk_level: str) -> dict:
    """What makes the file sensitive: its data findings' names and the file's risk level."""
    names: list[str] = []
    for finding in findings:
        label = str(finding.get("display_name") or finding.get("data_type") or finding.get("type") or "").strip()
        if label and label not in names:
            names.append(label)
    return {"data_types": names[:10], "data_finding_count": len(findings), "file_risk_level": risk_level}


def _grant_row(access: PrincipalAccess) -> dict:
    row = access.row()
    return {key: row[key] for key in (
        "key", "principal", "sid", "principal_type", "rights", "level", "denied_rights", "granted_by",
        "explicit_rights", "inherited_rights", "has_deny", "is_owner", "broad", "privileged", "service",
        "unresolved", "read", "write", "modify", "full_control", "change_permissions")}


def _grant_sentence(access: PrincipalAccess) -> str:
    source = access.granted_by or "no entry"
    deny = f"; denied {rights_label(access.denied)}" if access.denied else ""
    return f"{access.principal} - Allow {access.rights} ({source}){deny}"


def _remove_steps(path: str, accesses: list[PrincipalAccess], protected: bool | None) -> list[str]:
    """How to take each principal's risky access away - precise, and honest about what an
    inherited entry means: removing it on the file alone is not possible without changing
    how the file inherits."""
    steps: list[str] = []
    for access in accesses:
        if access.explicit_granted:
            steps.append(
                f"Remove the explicit entry granting {access.principal} {rights_label(access.explicit_granted)} on "
                f"this file (icacls \"{path}\" /remove:g *{access.sid or access.principal}), or replace it with a "
                "group that holds only the people who need the file.")
        if access.inherited_granted:
            steps.append(
                f"{access.principal}'s {rights_label(access.inherited_granted)} is inherited from a parent folder "
                "(Sentro did not resolve which one - the Advanced Security dialog's 'Inherited from' column, or "
                "Get-Acl on the parent folders, shows it). Narrow or remove the entry on that folder after "
                "confirming nothing else under it needs it, or move the file to a folder whose permissions "
                "already exclude the group. Removing it on this file alone means disabling inheritance and "
                "converting the inherited entries to explicit ones, after which changes to the parent folder no "
                "longer reach the file - do that only deliberately.")
    if protected:
        steps.append("Inheritance is disabled on this file: its entries were set on the file itself (or copied when "
                      "inheritance was turned off), so a change to a parent folder will not change them.")
    return steps


# What a finding says of the file's exposure (canonical_model's exposure states): a broad
# group that can write the file, one that can read it. The others keep the file's own.
EXPOSURE_STATES = {"access_broad_write": "WRITABLE_INTERNAL", "access_broad_read": "BROAD_INTERNAL"}


def _finding(kind: str, severity: str, rationale: str, description: str, path: str, owner: dict, grants: list[dict],
             steps: list[str], context: dict, extra: dict | None = None) -> dict:
    exposure = {
        "condition": kind, "principals": grants, "owner": owner, "severity_rationale": rationale,
        "sensitive_data": context, "access_model": MODEL_NOTE, "model_version": ACCESS_MODEL_VERSION,
        **(extra or {}),
    }
    finding = {
        "type": kind, "rule_id": kind, "rule_version": ACCESS_MODEL_VERSION, "access_finding": True,
        "category": ACCESS_CATEGORY, "finding_category": ACCESS_FINDING_CATEGORY, "data_category": ACCESS_CATEGORY,
        "data_type": "Access exposure", "classification_domain": "access_control",
        "display_name": DISPLAY_NAMES[kind], "description": description, "risk": severity,
        "impact_severity": severity, "confidence": 100, "frameworks": [], "framework": "",
        "occurrence_count": max(1, len(grants)), "unique_value_count": max(1, len(grants)),
        "samples": [], "access_exposure": exposure, "reason": rationale,
        "recommendations": steps + ["Sentro never changes permissions: apply the change on the file server, then "
                                    "scan again to confirm it."],
        "verification": [f"Get-Acl -LiteralPath '{path}' | Format-List Owner, AccessToString",
                         f"icacls \"{path}\""],
    }
    if kind in EXPOSURE_STATES:
        finding["exposure_state"] = EXPOSURE_STATES[kind]
    elif kind == "access_owner_risk" and owner.get("broad"):
        finding["exposure_state"] = "BROAD_INTERNAL"
    return finding


def derive(record: dict, data_findings: list[dict], *, risk_level: str = "") -> list[dict]:
    """The access findings of one analyzed record (see the module docstring)."""
    if not enabled() or not data_findings:
        return []
    acl = record.get("acl") if isinstance(record.get("acl"), dict) else {}
    if acl_state(acl) != "collected":
        return []
    path = str(record.get("path") or record.get("name") or "")
    accesses = principal_access(acl)
    owner = owner_of(acl)
    protected = acl.get("protected") if isinstance(acl.get("protected"), bool) else None
    context = _sensitive_context(data_findings, str(risk_level or "").upper())
    high_file = context["file_risk_level"] in ("CRITICAL", "HIGH")
    found: list[dict] = []

    broad = [access for access in accesses if access.broad and (access.read or access.write)]
    writers = [access for access in broad if access.write]
    if writers:
        severity = "HIGH" if high_file or any(access.full_control or access.change_permissions
                                              for access in writers) else "MEDIUM"
        if any(_anonymous(access) for access in writers):
            severity = _raise(severity)
        strongest = max(writers, key=lambda access: ("none", "special", "read", "write", "modify",
                                                     "full_control").index(access.level))
        rationale = (f"{strongest.principal} can {strongest.rights.lower()} a file holding "
                     f"{', '.join(context['data_types'][:3]) or 'sensitive data'}"
                     f"{' (file risk ' + context['file_risk_level'] + ')' if context['file_risk_level'] else ''}: "
                     "every member of the group can change or replace the data"
                     + ("; with full control or change permissions they can also re-grant or take ownership."
                        if any(access.full_control or access.change_permissions for access in writers) else "."))
        found.append(_finding(
            "access_broad_write", severity, rationale,
            f"{len(writers)} broad group(s) can write this sensitive file: "
            + "; ".join(_grant_sentence(access) for access in writers[:5]),
            path, owner, [_grant_row(access) for access in broad], _remove_steps(path, writers, protected), context,
            {"inheritance_disabled": protected}))
    elif broad:
        severity = "HIGH" if high_file else "MEDIUM"
        if any(_anonymous(access) for access in broad):
            severity = "HIGH"
        rationale = (f"{broad[0].principal} can read a file holding "
                     f"{', '.join(context['data_types'][:3]) or 'sensitive data'}"
                     f"{' (file risk ' + context['file_risk_level'] + ')' if context['file_risk_level'] else ''}: "
                     "every member of the group can open it, so the data is exposed far beyond its owners.")
        found.append(_finding(
            "access_broad_read", severity, rationale,
            f"{len(broad)} broad group(s) can read this sensitive file: "
            + "; ".join(_grant_sentence(access) for access in broad[:5]),
            path, owner, [_grant_row(access) for access in broad], _remove_steps(path, broad, protected), context,
            {"inheritance_disabled": protected}))

    if owner["key"] and (owner["broad"] or owner["type"] == "unresolved_sid"):
        severity = "HIGH" if owner["broad"] else "MEDIUM"
        who = "a broad group" if owner["broad"] else "a SID no authority could resolve"
        rationale = (f"The file's owner is {who} ({owner['name']}). An owner can always read the permissions and "
                     "change them (implicit READ_CONTROL and WRITE_DAC), whatever the entries say.")
        found.append(_finding(
            "access_owner_risk", severity, rationale, f"Owner: {owner['name']}"
            + (f" ({owner['sid']})" if owner["sid"] and owner["sid"] != owner["name"] else ""),
            path, owner, [_grant_row(access) for access in accesses if access.is_owner],
            [f"Set the owner to the data owner's account or a dedicated administrators group "
             f"(icacls \"{path}\" /setowner <account>), then review whether {owner['name']} still needs any "
             "entry."], context))

    unresolved = [access for access in accesses if access.unresolved and (access.read or access.write)]
    if unresolved:
        severity = "MEDIUM" if any(access.write for access in unresolved) else "LOW"
        rationale = (f"{len(unresolved)} entr{'y grants' if len(unresolved) == 1 else 'ies grant'} access to SIDs "
                     "that could not be resolved to an account - a deleted account, or one from a domain or server "
                     "Sentro cannot query. Who holds this access cannot be confirmed.")
        found.append(_finding(
            "access_unresolved_sid", severity, rationale,
            "; ".join(_grant_sentence(access) for access in unresolved[:5]), path, owner,
            [_grant_row(access) for access in unresolved],
            ["Ask the directory team whether each SID still belongs to an account (Get-ADObject -Filter "
             "\"objectSid -eq '<SID>'\"). If it does not, remove its entry:"]
            + _remove_steps(path, unresolved, protected), context))

    services = [access for access in accesses if access.service and access.read and not access.privileged]
    if services:
        severity = "MEDIUM" if any(access.sid.upper() in WEB_SERVICE_SIDS for access in services) else "LOW"
        rationale = (f"{', '.join(access.principal for access in services[:3])} can read this sensitive file. A "
                     "service identity reads on behalf of whoever reaches the service - a web request, an index "
                     "query - not only its administrators.")
        found.append(_finding(
            "access_service_read", severity, rationale,
            "; ".join(_grant_sentence(access) for access in services[:5]), path, owner,
            [_grant_row(access) for access in services],
            ["Confirm the service needs this file. If it does not, remove its entry or move the file out of the "
             "location the service serves or indexes:"] + _remove_steps(path, services, protected), context))

    readers = [access for access in accesses if access.read and not access.privileged]
    limit = max_principals()
    if len(readers) > limit:
        rationale = (f"{len(readers)} principals hold direct read access (the threshold is {limit}). The more "
                     "entries, the harder it is to tell who should have the data.")
        found.append(_finding(
            "access_excessive_principals", "LOW", rationale,
            f"{len(readers)} principals can read this sensitive file directly.", path, owner,
            [_grant_row(access) for access in readers[:50]],
            ["Replace the individual entries with one group the data owner manages, then remove the "
             "individual entries."], context, {"principal_count": len(readers)}))
    return found
