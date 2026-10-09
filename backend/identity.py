"""C2: who is signing in - found by workspace and sign-in name, locally or in the directory.

The account key (`users.username`) is internal and installation-unique; a person signs in
with their WORKSPACE (tenant) and their SIGN-IN NAME, unique within it. Without a
workspace the name is read as the account key, so every account that existed before
revision 0026 signs in exactly as it did.

Precedence, and why:

1. A LOCAL account with that sign-in name in the workspace is checked against its local
   password - never the directory. The built-in administrator is one, which is how an
   installation stays recoverable when its directory is down or misconfigured.
2. Otherwise, when the workspace has a directory enabled, the directory decides
   (backend.directory): password, account state, and groups mapped to a role. The first
   successful sign-in provisions a directory account (no local password); later ones
   bring its role and name in line with the directory.
3. Otherwise the sign-in fails - after the same password hashing a real attempt costs.

A directory account that is disabled, deleted or out of every mapped group is
deactivated and its sessions end, at its next sign-in attempt or the next refresh of an
existing session (`revalidate_directory_account`). A deactivated account - by the
directory or by a workspace administrator - stays so until an administrator reactivates
it: the directory password alone never brings it back.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from backend import directory, store
from backend.security import (
    Principal,
    _dummy_password_hash,
    authenticate_user,
    sanitize_username,
    verify_password,
)

DIRECTORY_PASSWORD_HASH = "!directory"


@dataclass
class SignIn:
    principal: Principal | None
    user: dict | None
    tenant_id: str
    attempted: str
    source: str = "local"
    failure: str = ""
    detail: str = ""


def workspace(value: object) -> str:
    return "".join(ch for ch in str(value or "").strip() if ch.isalnum() or ch in {"-", "_"})[:80]


def _refuse(tenant_id: str, attempted: str, source: str, failure: str, detail: str = "") -> SignIn:
    return SignIn(None, None, tenant_id, attempted, source, failure, detail)


def _burn(password: str) -> None:
    verify_password(password or "", _dummy_password_hash())


# ---- the directory's settings and service-account secret -------------------------
def directory_settings(tenant_id: str, *, enabled_only: bool = True) -> dict | None:
    settings = store.get_directory_settings(tenant_id)
    if settings is None or (enabled_only and not settings.get("enabled")):
        return None
    return settings


def bind_password(tenant_id: str, settings: dict) -> str:
    from backend.vault import CredentialVault

    ref = settings.get("bind_secret_ref") or ""
    if not ref:
        return ""
    try:
        return str(CredentialVault().resolve(tenant_id, ref, kind="directory").get("password") or "")
    except (KeyError, ValueError):
        return ""


def _end_directory_account(account: dict, reason: str) -> None:
    """The directory no longer vouches for this account: deactivate it and end its sessions."""
    store.update_directory_account(account["username"], role=account["role"], login_name=account["login_name"],
                                   full_name=account.get("full_name") or "", synced_at=int(time.time()), active=False)
    store.revoke_sessions_for_user(account["username"])
    store.audit(account["tenant_id"], account["username"], "auth.directory_account_disabled", {"reason": reason})


# ---- sign-in -------------------------------------------------------------------
def sign_in(username: str, password: str, workspace_id: str = "") -> SignIn:
    login = sanitize_username(username)
    tenant_id = workspace(workspace_id)
    if tenant_id:
        if not store.tenant_exists(tenant_id):
            _burn(password)
            return _refuse("default", login, "local", "invalid")
        user = store.find_user_by_login(tenant_id, login) if login else None
    else:
        user = store.get_user(login) if login else None
        tenant_id = str(user["tenant_id"]) if user else "default"

    if user is not None and user.get("auth_source", "local") == "local":
        principal = authenticate_user(login, password, user=user)
        return SignIn(principal, user if principal else None, tenant_id, login, "local", "" if principal else "invalid")

    settings = directory_settings(tenant_id)
    if settings is None:
        _burn(password)
        failure = "directory_disabled" if user is not None else "invalid"
        return _refuse(tenant_id, login, "ldap" if user else "local", failure,
                       "Directory sign-in is turned off for this workspace." if user else "")
    config = settings["config"]
    typed = username.strip()
    outcome = directory.authenticate(config, bind_password(tenant_id, settings), typed, password)
    now = int(time.time())
    existing = store.find_directory_user(tenant_id, outcome.external_id) if outcome.external_id else None
    if existing is None and user is not None and user.get("auth_source") == "ldap" and not (
            outcome.external_id and user.get("external_id") and outcome.external_id != user["external_id"]):
        # The account the name found is this directory entry unless the directory says it
        # is another one: a name reused by a new person does not inherit the old account.
        existing = user
    if not outcome.ok:
        # Only the directory's word about THIS account ends it - the entry carries its
        # identifier, or the name searched is exactly its name. A typed name that merely
        # sanitizes to someone else's ("alice#") must not sign them out (M3 exit review).
        about_this_account = existing is not None and (
            (outcome.external_id and outcome.external_id == existing.get("external_id"))
            or typed.casefold() == str(existing.get("login_name") or "").casefold())
        if about_this_account and outcome.status in {"disabled", "no_mapped_group", "not_found"} \
                and existing.get("is_active"):
            _end_directory_account(existing, outcome.status)
        return _refuse(tenant_id, login, "ldap", outcome.status, outcome.detail)
    if existing is not None and not existing.get("is_active"):
        # Suspended in Sentro - by an administrator, or by the directory earlier. The
        # directory password does not undo that; an administrator reactivates the account.
        return _refuse(tenant_id, login, "ldap", "inactive", "This account is suspended in this workspace.")

    display = outcome.display_name or login
    if existing is not None:
        before = existing["role"]
        account = store.update_directory_account(existing["username"], role=outcome.role, login_name=login,
                                                 full_name=display, synced_at=now, active=True)
        if before != outcome.role:
            store.audit(tenant_id, existing["username"], "auth.directory_role_changed",
                        {"from": before, "to": outcome.role, "group": outcome.matched_group})
    else:
        clash = store.find_user_by_login(tenant_id, login)
        key = None if clash is not None else store.allocate_account_key(login, tenant_id)
        if key is None:
            return _refuse(tenant_id, login, "ldap", "conflict",
                           "An account with that name already exists in this workspace.")
        account = store.create_user(key, DIRECTORY_PASSWORD_HASH, outcome.role, tenant_id, display, login_name=login,
                                    auth_source="ldap", external_id=outcome.external_id, directory_synced_at=now)
        store.audit(tenant_id, key, "auth.directory_account_created",
                    {"role": outcome.role, "group": outcome.matched_group})
    if account is None:
        return _refuse(tenant_id, login, "ldap", "invalid")
    store.mark_user_login(account["username"])
    principal = Principal(account["username"], account["role"], account["tenant_id"])
    return SignIn(principal, account, tenant_id, login, "ldap", "", outcome.matched_group)


def revalidate_directory_account(user: dict) -> str:
    """At session refresh: "ok" (groups current, role updated), "inactive" (the directory
    no longer vouches - sessions end) or "unavailable" (cannot tell - refuse to renew)."""
    if time.time() - int(user.get("directory_synced_at") or 0) < directory.revalidate_seconds():
        return "ok"
    tenant_id = str(user.get("tenant_id") or "default")
    settings = directory_settings(tenant_id)
    if settings is None:
        return "inactive"
    outcome = directory.lookup(settings["config"], bind_password(tenant_id, settings), user.get("login_name") or "")
    if outcome.status in {"disabled", "no_mapped_group", "not_found"}:
        _end_directory_account(user, outcome.status)
        return "inactive"
    if not outcome.ok:
        return "unavailable"
    if outcome.external_id and user.get("external_id") and outcome.external_id != user["external_id"]:
        # The name now belongs to a different directory entry: not the person who signed in.
        _end_directory_account(user, "identity_changed")
        return "inactive"
    before = user["role"]
    store.update_directory_account(user["username"], role=outcome.role, login_name=user["login_name"],
                                   full_name=outcome.display_name or user.get("full_name") or "",
                                   synced_at=int(time.time()), active=True)
    if before != outcome.role:
        store.audit(tenant_id, user["username"], "auth.directory_role_changed",
                    {"from": before, "to": outcome.role, "group": outcome.matched_group})
    return "ok"
