"""C2: sign-in through the customer's directory - Active Directory or LDAP.

The pilot's users are in Active Directory, and who may do what is already decided there,
by group. So a workspace can name its directory, and a person signs in with their
directory account: Sentro checks the password against the directory and maps the groups
the directory reports onto one of the workspace's roles - built-in or custom, the C3
permission catalogue, not a second authorization system.

What it refuses to do, on purpose:

* **Plain LDAP.** A simple bind sends the password, so the connection is LDAPS or
  StartTLS, and the certificate is verified - against the system store or a CA the
  administrator uploads, never "accept anything". A certificate that does not verify
  is a failed sign-in, not a fallback.
* **An empty password.** LDAP treats a simple bind with an empty password as an
  anonymous bind that SUCCEEDS; it is refused before the directory is asked.
* **A guess.** A directory that cannot be reached, answers ambiguously (two entries for
  one name) or reports no mapped group is a refusal. Nothing falls back to a local
  password: a directory account has none.
* **Stale privilege.** Groups are read at every sign-in and re-read at least every
  `DSPM_DIRECTORY_REVALIDATE_SECONDS` when the session refreshes (with the read-only
  service account); an account that lost its last mapped group, or was disabled, loses
  its sessions at the next refresh. Removed privilege lasts at most one access token.

The service account's password is kept in the vault (never returned, never logged); the
rest of the configuration is ordinary settings. Mappings are ordered: the first group in
the list that the person belongs to decides their role, so list the most privileged first.
"""

from __future__ import annotations

import os
import re
import ssl
from dataclasses import dataclass, field

SECURITY = ("ldaps", "starttls")
DEFAULT_PORTS = {"ldaps": 636, "starttls": 389}
TRUST = ("system", "custom")
USER_ATTRIBUTES = ("sAMAccountName", "userPrincipalName", "uid", "mail")
GROUP_SEARCH = ("memberof", "ad_nested")
MAX_MAPPINGS = 50
TIMEOUT_SECONDS = (1, 60)
# AD's userAccountControl ACCOUNTDISABLE bit.
_AD_DISABLED = 0x2
# The directory's own stable identifier, most specific first.
_ID_ATTRIBUTES = ("objectGUID", "entryUUID", "nsUniqueId", "ipaUniqueID")
_DN = re.compile(r"^(?:[A-Za-z][\w-]*|\d+(?:\.\d+)+)=[^,]+(?:,(?:[A-Za-z][\w-]*|\d+(?:\.\d+)+)=[^,]+)*$")


def revalidate_seconds() -> int:
    """How long a directory account's groups are trusted before a refresh re-reads them."""
    try:
        value = int(os.getenv("DSPM_DIRECTORY_REVALIDATE_SECONDS", "900"))
    except ValueError:
        value = 900
    return max(60, min(value, 3600))


class DirectoryError(ValueError):
    """A configuration the administrator must correct; its message is shown to them."""

    client_safe = True


@dataclass
class Outcome:
    """What the directory said about one sign-in or one look-up."""
    status: str  # ok | invalid_credentials | not_found | disabled | no_mapped_group | unavailable | tls_failure | misconfigured
    role: str = ""
    login_name: str = ""
    external_id: str = ""
    display_name: str = ""
    groups: tuple = ()
    matched_group: str = ""
    detail: str = ""
    dn: str = field(default="", repr=False)

    @property
    def ok(self) -> bool:
        return self.status == "ok"


# ---- configuration --------------------------------------------------------------
def _dn(value: object, what: str, required: bool = True) -> str:
    text = " ".join(str(value or "").split())
    if not text:
        if required:
            raise DirectoryError(f"Enter the {what}.")
        return ""
    if len(text) > 400 or not _DN.match(text):
        raise DirectoryError(f"The {what} must be a distinguished name, such as OU=Users,DC=corp,DC=example.")
    return text


def validate(request: dict, saved: dict | None, role_exists) -> dict:
    """The configuration to store (no secret), from what the administrator sent and what
    is already saved. `role_exists(role)` answers for this workspace's roles."""
    from backend.siem_settings import SiemSettingsError, ca_metadata, validate_host

    saved = dict(saved or {})
    try:
        host = validate_host(request.get("host", saved.get("host")))
    except SiemSettingsError as exc:
        raise DirectoryError(str(exc)) from exc
    security = str(request.get("security", saved.get("security") or "ldaps")).lower()
    if security not in SECURITY:
        raise DirectoryError("Connect with LDAPS or StartTLS. Plain LDAP would send passwords unencrypted.")
    port = request.get("port", saved.get("port")) or DEFAULT_PORTS[security]
    try:
        port = int(port)
    except (TypeError, ValueError) as exc:
        raise DirectoryError("The port must be a number.") from exc
    if not 1 <= port <= 65535:
        raise DirectoryError("The port must be between 1 and 65535.")
    trust = str(request.get("trust", saved.get("trust") or "system")).lower()
    if trust not in TRUST:
        raise DirectoryError("Trust the system certificate store or an uploaded CA certificate.")
    config = {"host": host, "port": port, "security": security, "trust": trust}
    ca_keys = ("ca_pem", "ca_name", "ca_fingerprint", "ca_subject", "ca_not_after", "ca_count")
    if trust == "custom":
        if request.get("ca_pem"):
            try:
                config.update(ca_metadata(request["ca_pem"], request.get("ca_name") or "ca.pem"))
            except SiemSettingsError as exc:
                raise DirectoryError(str(exc)) from exc
        elif saved.get("ca_pem"):
            config.update({key: saved[key] for key in ca_keys if key in saved})
        else:
            raise DirectoryError("Upload the CA certificate that signed the directory's certificate.")
    config["base_dn"] = _dn(request.get("base_dn", saved.get("base_dn")), "user search base")
    config["bind_dn"] = _dn(request.get("bind_dn", saved.get("bind_dn")), "service account (bind DN)")
    attribute = str(request.get("user_attribute", saved.get("user_attribute") or "sAMAccountName"))
    if attribute not in USER_ATTRIBUTES:
        raise DirectoryError(f"Find users by one of: {', '.join(USER_ATTRIBUTES)}.")
    config["user_attribute"] = attribute
    group_search = str(request.get("group_search", saved.get("group_search") or "memberof")).lower()
    if group_search not in GROUP_SEARCH:
        raise DirectoryError("Read groups from memberOf, or through Active Directory's nested-group rule.")
    config["group_search"] = group_search
    config["group_base_dn"] = _dn(request.get("group_base_dn", saved.get("group_base_dn") or ""),
                                  "group search base", required=group_search == "ad_nested")
    try:
        timeout = int(request.get("timeout_seconds", saved.get("timeout_seconds") or 10))
    except (TypeError, ValueError) as exc:
        raise DirectoryError("The timeout must be a number of seconds.") from exc
    config["timeout_seconds"] = max(TIMEOUT_SECONDS[0], min(timeout, TIMEOUT_SECONDS[1]))
    mappings = request.get("mappings", saved.get("mappings") or [])
    if not isinstance(mappings, list) or not mappings:
        raise DirectoryError("Map at least one directory group to a role; nobody can sign in otherwise.")
    if len(mappings) > MAX_MAPPINGS:
        raise DirectoryError(f"Map at most {MAX_MAPPINGS} groups.")
    cleaned = []
    for item in mappings:
        group = _dn((item or {}).get("group_dn"), "group")
        role = str((item or {}).get("role") or "").strip().lower()
        if not role_exists(role):
            raise DirectoryError(f"Unknown role in this workspace: {role or '(none)'}.")
        cleaned.append({"group_dn": group, "role": role})
    config["mappings"] = cleaned
    return config


def public_view(settings: dict | None, *, editable: bool) -> dict:
    """What the console is shown: everything but the service account's password, whose
    presence is a flag."""
    if not settings:
        return {"configured": False, "enabled": False, "editable": editable, "config": {},
                "bind_password_configured": False}
    config = {key: value for key, value in (settings.get("config") or {}).items() if key != "ca_pem"}
    return {"configured": True, "enabled": bool(settings.get("enabled")), "editable": editable, "config": config,
            "bind_password_configured": bool(settings.get("bind_secret_ref")),
            "updated_by": settings.get("updated_by", ""), "updated_at": settings.get("updated_at", "")}


def map_role(config: dict, groups) -> tuple[str, str]:
    """(role, group) for the first mapping the person's groups include, else ("", "")."""
    held = {str(group).strip().lower() for group in groups}
    for mapping in config.get("mappings") or []:
        if str(mapping.get("group_dn", "")).strip().lower() in held:
            return mapping["role"], mapping["group_dn"]
    return "", ""


# ---- talking to the directory ----------------------------------------------------
class _Failure(Exception):
    def __init__(self, status: str, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


def _server(config: dict):
    import ldap3

    ca_pem = config.get("ca_pem") if config.get("trust") == "custom" else None
    tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLS_CLIENT, ca_certs_data=ca_pem)
    return ldap3.Server(config["host"], port=int(config["port"]), use_ssl=config["security"] == "ldaps", tls=tls,
                        get_info=ldap3.NONE, connect_timeout=int(config.get("timeout_seconds") or 10))


def _connection(server, user: str, password: str, config: dict):
    """The one place a connection is made - tests replace it with ldap3's MOCK_SYNC."""
    import ldap3

    return ldap3.Connection(server, user=user, password=password, auto_bind=ldap3.AUTO_BIND_NONE, read_only=True,
                            receive_timeout=int(config.get("timeout_seconds") or 10), raise_exceptions=False)


def _classify(exc: BaseException) -> _Failure:
    text = f"{type(exc).__name__}: {exc}".lower()
    if any(marker in text for marker in ("certificate", "ssl", "tls", "handshake", "hostname")):
        return _Failure("tls_failure", "The directory's certificate could not be verified.")
    return _Failure("unavailable", "The directory could not be reached.")


def _bind(config: dict, user: str, password: str):
    """A bound connection, with TLS in force before any password is sent."""
    if not password:
        raise _Failure("invalid_credentials", "No password was given.")
    try:
        server = _server(config)
        connection = _connection(server, user, password, config)
        if config["security"] == "starttls" and not _is_mock(connection):
            # Upgrade before the bind: the password must never cross in the clear.
            connection.open()
            if not connection.start_tls():
                raise _Failure("tls_failure", "The directory refused StartTLS.")
        if not connection.bind():
            result = getattr(connection, "result", None) or {}
            code = int(result.get("result", 49) or 49) if isinstance(result, dict) else 49
            if code in (49, 50, 53):  # invalidCredentials, insufficientAccessRights, unwillingToPerform
                raise _Failure("invalid_credentials", "The directory refused the credentials.")
            raise _Failure("unavailable", "The directory could not complete the sign-in.")
        return connection
    except _Failure:
        raise
    except Exception as exc:  # the ldap3 exception family, socket and TLS errors
        raise _classify(exc) from None


def _is_mock(connection) -> bool:
    return "Mock" in type(getattr(connection, "strategy", None)).__name__


def _first(entry, name: str) -> str:
    values = entry.get(name) or []
    if isinstance(values, (bytes, str)):
        values = [values]
    for value in values:
        if isinstance(value, bytes):
            return value.hex()
        if str(value).strip():
            return str(value).strip()
    return ""


def _find_user(connection, config: dict, login: str) -> tuple[str, dict]:
    from ldap3 import SUBTREE
    from ldap3.utils.conv import escape_filter_chars

    attribute = config["user_attribute"]
    query = f"(&(|(objectClass=person)(objectClass=user)(objectClass=inetOrgPerson))({attribute}={escape_filter_chars(login)}))"
    wanted = [*_ID_ATTRIBUTES, "memberOf", "userAccountControl", "displayName", "cn", "pwdAccountLockedTime",
              "nsAccountLock", attribute]
    if not connection.search(config["base_dn"], query, SUBTREE, attributes=wanted, size_limit=2):
        return "", {}
    entries = list(connection.entries)
    if len(entries) != 1:
        # None, or two entries for one name - which would be a guess either way.
        return "", {}
    entry = entries[0]
    return entry.entry_dn, {key: list(value) if isinstance(value, (list, tuple)) else value
                            for key, value in entry.entry_attributes_as_dict.items()}


def _groups(connection, config: dict, dn: str, attributes: dict) -> tuple:
    groups = [str(value) for value in attributes.get("memberOf") or []]
    if config.get("group_search") == "ad_nested":
        from ldap3 import SUBTREE
        from ldap3.utils.conv import escape_filter_chars

        # LDAP_MATCHING_RULE_IN_CHAIN: every group the user is in, directly or not.
        query = f"(member:1.2.840.113556.1.4.1941:={escape_filter_chars(dn)})"
        if connection.search(config["group_base_dn"], query, SUBTREE, attributes=["cn"]):
            groups.extend(entry.entry_dn for entry in connection.entries)
    return tuple(dict.fromkeys(groups))


def _disabled(attributes: dict) -> bool:
    control = _first(attributes, "userAccountControl")
    if control.isdigit() and int(control) & _AD_DISABLED:
        return True
    if _first(attributes, "pwdAccountLockedTime"):
        return True
    return _first(attributes, "nsAccountLock").lower() == "true"


def _outcome(config: dict, login: str, dn: str, attributes: dict, groups: tuple) -> Outcome:
    external = next((_first(attributes, name) for name in _ID_ATTRIBUTES if _first(attributes, name)), dn.lower())
    display = _first(attributes, "displayName") or _first(attributes, "cn")
    if _disabled(attributes):
        return Outcome("disabled", login_name=login, external_id=external, display_name=display, groups=groups, dn=dn,
                       detail="The directory account is disabled.")
    role, group = map_role(config, groups)
    if not role:
        return Outcome("no_mapped_group", login_name=login, external_id=external, display_name=display, groups=groups,
                       dn=dn, detail="The account is in none of the groups mapped to a role.")
    return Outcome("ok", role=role, login_name=login, external_id=external, display_name=display, groups=groups,
                   matched_group=group, dn=dn)


def authenticate(config: dict, bind_password: str, login: str, password: str) -> Outcome:
    """Check a person's password with the directory and map their groups to a role."""
    login = str(login or "").strip()
    if not login or not password:
        return Outcome("invalid_credentials", login_name=login, detail="Enter a user name and password.")
    try:
        service = _bind(config, config["bind_dn"], bind_password)
    except _Failure as failure:
        status = "misconfigured" if failure.status == "invalid_credentials" else failure.status
        return Outcome(status, login_name=login, detail="The directory service account could not sign in."
                       if status == "misconfigured" else failure.detail)
    try:
        dn, attributes = _find_user(service, config, login)
        if not dn:
            return Outcome("not_found", login_name=login, detail="No single directory account has that name.")
        try:
            person = _bind(config, dn, password)
        except _Failure as failure:
            return Outcome(failure.status, login_name=login, detail=failure.detail)
        _unbind(person)
        return _outcome(config, login, dn, attributes, _groups(service, config, dn, attributes))
    except _Failure as failure:
        return Outcome(failure.status, login_name=login, detail=failure.detail)
    except Exception as exc:  # a search that failed mid-way
        failure = _classify(exc)
        return Outcome(failure.status, login_name=login, detail=failure.detail)
    finally:
        _unbind(service)


def lookup(config: dict, bind_password: str, login: str) -> Outcome:
    """Re-read an account's groups and state without its password (session refresh)."""
    try:
        service = _bind(config, config["bind_dn"], bind_password)
    except _Failure as failure:
        status = "misconfigured" if failure.status == "invalid_credentials" else failure.status
        return Outcome(status, login_name=login, detail=failure.detail)
    try:
        dn, attributes = _find_user(service, config, login)
        if not dn:
            return Outcome("not_found", login_name=login, detail="The directory no longer has that account.")
        return _outcome(config, login, dn, attributes, _groups(service, config, dn, attributes))
    except Exception as exc:
        failure = _classify(exc)
        return Outcome(failure.status, login_name=login, detail=failure.detail)
    finally:
        _unbind(service)


def test(config: dict, bind_password: str, login: str = "") -> dict:
    """What the Test button reports: the service account binds, the user base can be
    searched, and - given a name - which role that person would get. No password of the
    person is involved, and nothing is provisioned."""
    try:
        service = _bind(config, config["bind_dn"], bind_password)
    except _Failure as failure:
        status = "misconfigured" if failure.status == "invalid_credentials" else failure.status
        return {"ok": False, "status": status,
                "message": "The service account could not sign in." if status == "misconfigured" else failure.detail}
    try:
        report = {"ok": True, "status": "connected", "message": "The service account signed in over "
                  + ("LDAPS" if config["security"] == "ldaps" else "StartTLS") + "."}
        if login:
            dn, attributes = _find_user(service, config, login)
            if not dn:
                report.update({"ok": False, "status": "not_found", "message": "No single directory account has that name."})
            else:
                outcome = _outcome(config, login, dn, attributes, _groups(service, config, dn, attributes))
                report.update({"ok": outcome.ok, "status": outcome.status, "role": outcome.role,
                               "matched_group": outcome.matched_group, "group_count": len(outcome.groups),
                               "message": outcome.detail or f"{login} would sign in as {outcome.role}."})
        return report
    except Exception as exc:
        failure = _classify(exc)
        return {"ok": False, "status": failure.status, "message": failure.detail}
    finally:
        _unbind(service)


def _unbind(connection) -> None:
    try:
        connection.unbind()
    except Exception:  # already closed, or never opened
        pass
