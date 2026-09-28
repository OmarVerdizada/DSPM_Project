"""Does a saved scan credential hold more privilege than scanning needs? (C12)

Scanning reads files and ACLs; it never needs to administer a domain. An account in
Domain Admins works - and turns every saved-credential leak into a domain compromise -
so the product says so when a credential is saved, and again on request.

What is checked:
* when the workspace has directory sign-in configured (C2), the account is looked up with
  the read-only service account: membership of a privileged group, and Active
  Directory's `adminCount` (set on every account a protected group reaches, nested
  membership included);
* in every case, the name: the built-in Administrator and names that say "admin".

A warning never blocks saving - the operator may have no other account today - but it is
shown with the credential, audited, and kept until the credential is checked again.
"""

from __future__ import annotations

from datetime import datetime, timezone

# Groups whose members can take over a domain or a server (Microsoft's protected
# groups, plus the local Administrators alias).
PRIVILEGED_GROUPS = (
    "domain admins", "enterprise admins", "schema admins", "administrators", "account operators",
    "server operators", "backup operators", "print operators", "group policy creator owners",
    "dnsadmins", "key admins", "enterprise key admins", "cert publishers",
)
ADMIN_NAMES = {"administrator", "admin", "root", "domainadmin"}


def _group_name(dn: str) -> str:
    first = str(dn).split(",", 1)[0]
    return first.split("=", 1)[-1].strip().lower() if "=" in first else first.strip().lower()


def _account_name(username: str) -> str:
    name = str(username or "").strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name


def by_name(username: str) -> list[str]:
    name = _account_name(username).lower()
    if name in ADMIN_NAMES:
        return [f"'{_account_name(username)}' is the name of a built-in administrator account."]
    if name.startswith(("adm-", "admin-", "adm_", "admin_")) or name.endswith(("-admin", "_admin", "-adm", "_adm", "admin")):
        return [f"'{_account_name(username)}' is named like an administrator account."]
    return []


def assess(tenant_id: str, username: str, domain: str = "") -> dict:
    """{"level": "excessive"|"warning"|"ok"|"unchecked", "findings": [...], "source", "checked_at"}."""
    findings = by_name(username)
    source = "name"
    level = "warning" if findings else "unchecked"
    try:
        from backend import directory, identity

        settings = identity.directory_settings(tenant_id)
    except Exception:
        settings = None
    if settings is not None:
        source = "directory"
        outcome = directory.lookup(settings["config"], identity.bind_password(tenant_id, settings),
                                   _account_name(username))
        if outcome.status in {"ok", "no_mapped_group", "disabled"}:
            privileged = sorted({_group_name(group) for group in outcome.groups} & set(PRIVILEGED_GROUPS))
            if privileged:
                findings.append("Member of " + ", ".join(name.title() for name in privileged) + ".")
            if getattr(outcome, "admin_count", False):
                findings.append("Active Directory marks the account as protected (adminCount=1): a privileged "
                                "group reaches it, possibly through nesting.")
            if outcome.status == "disabled":
                findings.append("The directory account is disabled; scans with it will fail.")
            level = "excessive" if (privileged or getattr(outcome, "admin_count", False)) else (
                "warning" if findings else "ok")
        elif outcome.status == "not_found":
            findings.append("The workspace's directory has no account by this name (a local account on the target?).")
        else:
            findings.append(f"The directory could not be asked ({outcome.status}); only the name was checked.")
            source = "name"
    return {"level": level, "findings": findings, "source": source,
            "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "advice": ("Scanning needs read access to the shares and their ACLs, nothing more. Use a dedicated "
                       "account with read rights (docs/ENDPOINT_LEAST_PRIVILEGE.md)." if level in {"excessive", "warning"}
                       else "")}
