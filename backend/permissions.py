"""What a role may do, named (C3).

Authorization used to be three ranks - viewer < analyst < admin - and a route said the
lowest rank it accepted. A rank cannot express that someone may run scans without
reading what the scans found, or read the audit trail without changing anything, and
it put every read behind the same door: a viewer could export the inventory, file a
report and download the full scan report, because those were reads.

Each route now names ONE capability it needs (`backend.security.require_permission`),
and a role is a set of capabilities. The names are the contract: the route matrix in
tests/test_route_permissions.py pins every route to one of them, so a new route cannot
be added without deciding which.

`platform.admin` is not assignable to a role. It belongs to the installation's own
administrator identity (see `security.is_platform_admin`), because what it guards -
tenants, legal holds, the shared NIST catalogue, install-wide settings and database
diagnostics - crosses every tenant, and no tenant's role should reach it.
"""

from __future__ import annotations

# Self-service: any signed-in account, for its own profile, password and sign-out.
AUTHENTICATED = "authenticated"

PERMISSIONS: dict[str, str] = {
    "inventory.view": "See the inventory, findings, dashboards and scan history",
    "evidence.view": "See evidence: file previews and the matched values behind a finding",
    "findings.triage": "Assign, comment on, validate, resolve, suppress and reopen findings",
    "scan.run": "Configure, schedule and run scans, test connections and prepare endpoints",
    "credential.manage": "Save credentials in the vault for scans to use",
    "rules.manage": "Change suppression rules and keyword libraries, validate catalogues",
    "export": "Export the inventory, keyword libraries, catalogues and DLP policies",
    "report.create": "File assessment reports and download them",
    "audit.view": "Read the audit trail and sign-in activity",
    "tenant.admin": "Manage this tenant's users, roles, invites, registration codes and API keys",
    "platform.admin": "Operate the installation: tenants, legal holds, the NIST catalogue, "
                      "install-wide settings and database diagnostics",
}

# Held by the installation's administrator identity, never by a role.
PLATFORM_ONLY = frozenset({"platform.admin"})

_ALL_ASSIGNABLE = frozenset(PERMISSIONS) - PLATFORM_ONLY

# Built-in roles, least to most. Their names are what users.role, invites and API keys
# store. `analyst` keeps exactly what it could do before C3. `viewer` loses what a
# read-only account should never have had (export and reports). `admin` keeps its whole
# tenant, but not the install-wide controls rank alone used to hand it - OCR for every
# tenant, database diagnostics - which are the platform administrator's.
BUILTIN_ROLES: dict[str, dict] = {
    "viewer": {
        "label": "Viewer",
        "description": "Reads dashboards, the inventory and findings. Cannot export, file reports or change anything.",
        "permissions": frozenset({"inventory.view"}),
    },
    "auditor": {
        "label": "Auditor",
        "description": "Reads everything a viewer does, plus the audit trail, and files reports. Changes nothing.",
        "permissions": frozenset({"inventory.view", "audit.view", "report.create"}),
    },
    "scan_operator": {
        "label": "Scan operator",
        "description": "Runs and schedules scans and prepares endpoints. Sees results, not evidence.",
        "permissions": frozenset({"inventory.view", "scan.run"}),
    },
    "analyst": {
        "label": "Analyst",
        "description": "Works the findings: evidence, triage, rules, scans, exports and reports.",
        "permissions": frozenset({
            "inventory.view", "evidence.view", "findings.triage", "scan.run", "credential.manage",
            "rules.manage", "export", "report.create",
        }),
    },
    "admin": {
        "label": "Tenant administrator",
        "description": "Everything in this tenant, including its users, roles and API keys.",
        "permissions": _ALL_ASSIGNABLE,
    },
}

# Roles an invite or an API key may carry: never one that administers the tenant.
# An administrator is made deliberately, through the user routes.
DELEGABLE_ROLES = tuple(name for name, role in BUILTIN_ROLES.items() if "tenant.admin" not in role["permissions"])


def is_known_role(role: str) -> bool:
    return str(role or "") in BUILTIN_ROLES


def role_permissions(role: str) -> frozenset[str]:
    """What a role may do. An unknown role may do nothing."""
    entry = BUILTIN_ROLES.get(str(role or ""))
    return entry["permissions"] if entry else frozenset()


def role_catalogue() -> list[dict]:
    """The roles and what each allows, for an administrator choosing one."""
    return [
        {"name": name, "label": role["label"], "description": role["description"],
         "permissions": sorted(role["permissions"]), "builtin": True}
        for name, role in BUILTIN_ROLES.items()
    ]


def permission_catalogue() -> list[dict]:
    return [{"name": name, "description": text, "assignable": name not in PLATFORM_ONLY}
            for name, text in PERMISSIONS.items()]
