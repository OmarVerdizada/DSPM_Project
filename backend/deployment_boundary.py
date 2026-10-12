"""What a production install must be reachable by, and by nothing else (C5).

The supported production shape is the backend on the loopback interface, behind an
HTTPS reverse proxy on the same host (deploy/reverse-proxy). Each rule here is a
configuration that has been seen to fail open, so production refuses to start with it
rather than log it:

* no trusted host names, or a wildcard among them - the Host header then decides what
  the console believes its own name is;
* a cross-origin list with a wildcard, a localhost origin or a plain-HTTP origin - the
  API sends credentials to every origin on the list;
* a trusted proxy that is not an address, or trusts every address - any client could
  then choose the address it is audited and throttled as;
* serving on an interface other than loopback without saying so - the backend itself
  does not speak TLS;
* serving on loopback with no trusted proxy - then every request comes from the proxy,
  every audit row names it, and one attacker's failed sign-ins lock every user out.

Development (DSPM_ENV other than production) is not checked.
"""

from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlsplit

from backend.client_address import trusted_proxies, trusted_proxy_problems

LOCAL_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}
# A development convenience only. The console is served by the backend itself and needs
# no cross-origin access, so production has no default list at all.
DEVELOPMENT_CORS_ORIGINS = (
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://127.0.0.1:3000",
    "http://localhost:3000",
)


def is_production() -> bool:
    return os.getenv("DSPM_ENV", "local").strip().lower() in {"prod", "production"}


def _listed(value: str) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def trusted_hosts_setting() -> list[str]:
    return _listed(os.getenv("DSPM_TRUSTED_HOSTS", ""))


def cors_origins_setting() -> list[str]:
    default = "" if is_production() else ",".join(DEVELOPMENT_CORS_ORIGINS)
    return _listed(os.getenv("DSPM_CORS_ORIGINS", default))


def _is_local_host(host: str) -> bool:
    host = (host or "").strip().strip("[]").lower().rstrip(".")
    if host in LOCAL_NAMES or host.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_unspecified


def _is_loopback_bind(host: str) -> bool:
    host = (host or "").strip().strip("[]").lower()
    if host in LOCAL_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def host_problems(trusted_hosts: list[str]) -> list[str]:
    if not trusted_hosts:
        return ["DSPM_TRUSTED_HOSTS is empty: set it to the host name(s) the console is reached by, "
                "e.g. DSPM_TRUSTED_HOSTS=sentro.corp.example"]
    return [f"DSPM_TRUSTED_HOSTS entry {host!r} is a wildcard: name each host the console is reached by"
            for host in trusted_hosts if "*" in host]


def origin_problems(origins: list[str]) -> list[str]:
    problems = []
    for origin in origins:
        if "*" in origin:
            problems.append(f"DSPM_CORS_ORIGINS entry {origin!r} is a wildcard, and the API sends credentials "
                            "to every listed origin")
            continue
        parts = urlsplit(origin)
        if parts.scheme != "https":
            problems.append(f"DSPM_CORS_ORIGINS entry {origin!r} is not an https:// origin")
        if not parts.hostname or _is_local_host(parts.hostname):
            problems.append(f"DSPM_CORS_ORIGINS entry {origin!r} is a local origin: any program on a user's "
                            "machine could call the API with their session")
    return problems


def bind_problems(bind_host: str) -> list[str]:
    if _is_loopback_bind(bind_host):
        networks = trusted_proxies()
        try:
            loopback = ipaddress.ip_address("::1" if ":" in bind_host else "127.0.0.1")
        except ValueError:  # pragma: no cover - both literals are valid
            loopback = None
        if not any(loopback in network for network in networks):
            return ["serving on loopback, so a reverse proxy on this host is the only way in, but "
                    "DSPM_TRUSTED_PROXIES does not name it: every client would be the proxy. "
                    "Set DSPM_TRUSTED_PROXIES=127.0.0.1"]
        return []
    if os.getenv("DSPM_ALLOW_EXTERNAL_BIND", "").strip() == "1":
        return []
    return [f"serving on {bind_host!r}, not loopback: the backend does not speak TLS. Serve on 127.0.0.1 "
            "behind the HTTPS reverse proxy (deploy/reverse-proxy), or set DSPM_ALLOW_EXTERNAL_BIND=1 when "
            "TLS ends on another host that alone can reach this one"]


def production_problems(trusted_hosts: list[str], cors_origins: list[str], bind_host: str | None = None) -> list[str]:
    problems = host_problems(trusted_hosts) + origin_problems(cors_origins) + trusted_proxy_problems()
    if bind_host is not None:
        problems += bind_problems(bind_host)
    return problems


def refusal(problems: list[str]) -> str:
    return ("Refusing to start in production:\n  - " + "\n  - ".join(problems)
            + "\nSee deploy/reverse-proxy/README.md (C5).")


def enforce(trusted_hosts: list[str], cors_origins: list[str], bind_host: str | None = None) -> None:
    """Raise RuntimeError naming every problem, in production only."""
    if not is_production():
        return
    problems = production_problems(trusted_hosts, cors_origins, bind_host)
    if problems:
        raise RuntimeError(refusal(problems))
