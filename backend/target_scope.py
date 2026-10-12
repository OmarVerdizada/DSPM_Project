"""Which hosts a workspace may scan (C5).

Each workspace keeps a list of the networks (an address or CIDR) and host names (exact,
or `*.corp.example` for the names under a domain) it may scan. It replaces the single
install-wide DSPM_ALLOW_PRIVATE_TARGETS switch, under which every workspace could scan
every private address or none could.

One decision, made in two places so that no path round it: the API asks before a scan
is accepted, and the collectors ask again when they connect (scheduled, queued and
resumed scans never pass the API). It is made on the addresses the name resolved to,
which the collectors then dial - so a name re-pointed after the check still cannot
reach an address outside the list (collectors/net_guard).

* An address that is never a scan target - loopback, link-local, multicast, reserved,
  unspecified, cloud metadata - is refused whatever the list says.
* A name on the list is in scope.
* Otherwise every address the name resolves to must be inside a listed network.
* A workspace with no list: in production nothing is in scope, so an install scans
  nothing until an administrator says what; in development, everything else is.

A refusal is audited in the workspace that asked, and the collector never connects.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field

from collectors.net_guard import ip_disallowed_reason, resolve_addresses

MAX_ENTRIES = 500
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOSTNAME = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})*$")


class TargetScopeError(ValueError):
    """A refused entry; the text is written for the administrator and safe to show."""

    client_safe = True


def _is_production() -> bool:
    return os.getenv("DSPM_ENV", "local").strip().lower() in {"prod", "production"}


def parse_entry(value: str) -> tuple[str, str]:
    """(kind, normalised value) for one list entry: ("network", "10.1.0.0/16") or
    ("host", "fs01.corp.example") / ("host", "*.corp.example")."""
    text = str(value or "").strip().lower().rstrip(".")
    if not text:
        raise TargetScopeError("Enter a network (10.1.0.0/16 or an address) or a host name.")
    if len(text) > 253:
        raise TargetScopeError("That entry is too long.")
    if "://" in text or " " in text:
        raise TargetScopeError("Enter only the address, network or host name - no scheme, port or path.")
    try:
        network = ipaddress.ip_network(text.strip("[]"), strict=False)
    except ValueError:
        network = None
    if network is not None:
        if network.prefixlen == 0:
            raise TargetScopeError("A network that contains every address is not a scope. List the networks the file servers are in.")
        if network.is_loopback or network.is_link_local or network.is_multicast or network.is_unspecified or network.is_reserved:
            raise TargetScopeError(f"{network} is never a scan target (loopback, link-local, multicast or reserved).")
        return "network", str(network)
    if "/" in text:
        raise TargetScopeError("That is not a valid network. Use an address with a prefix length, such as 10.1.0.0/16.")
    wildcard = text.startswith("*.")
    name = text[2:] if wildcard else text
    if "*" in name or not _HOSTNAME.match(name):
        raise TargetScopeError("That is not a valid host name. A wildcard may only stand for the names under a domain: *.corp.example.")
    if wildcard and "." not in name:
        raise TargetScopeError("A wildcard needs a domain with at least two labels, such as *.corp.example.")
    return "host", text


@dataclass(frozen=True)
class Scope:
    tenant_id: str
    networks: tuple = field(default_factory=tuple)
    hosts: tuple = field(default_factory=tuple)

    @property
    def defined(self) -> bool:
        return bool(self.networks or self.hosts)

    def names(self, host: str) -> bool:
        name = str(host or "").strip().lower().rstrip(".")
        for entry in self.hosts:
            if entry.startswith("*."):
                if name.endswith(entry[1:]) and name != entry[2:]:
                    return True
            elif name == entry:
                return True
        return False

    def contains(self, address) -> bool:
        return any(address.version == network.version and address in network for network in self.networks)


def scope_for(tenant_id: str | None) -> Scope:
    if not tenant_id:
        return Scope("")
    from backend import store

    networks, hosts = [], []
    for entry in store.list_scan_targets(tenant_id):
        if entry["kind"] == "network":
            networks.append(ipaddress.ip_network(entry["value"], strict=False))
        else:
            hosts.append(entry["value"])
    return Scope(tenant_id, tuple(networks), tuple(hosts))


def decide(scope: Scope, host: str, addresses: list) -> str | None:
    """Why `host` (resolving to `addresses`) may not be scanned, or None if it may."""
    for address in addresses:
        reason = ip_disallowed_reason(address, allow_private=True)
        if reason:
            return f"{host} resolves to {address}, which is never a scan target ({reason})."
    if not scope.defined:
        if _is_production():
            return ("No scan targets are defined for this workspace, so nothing on the network can be scanned. "
                    "An administrator adds them under Security operations → Scan targets.")
        return None
    if scope.names(host):
        return None
    if not addresses:
        return f"{host} could not be resolved, and it is not listed by name in this workspace's scan targets."
    outside = [str(address) for address in addresses if not scope.contains(address)]
    if outside:
        return (f"{host} is not in this workspace's scan targets"
                + ("." if outside == [str(host).strip("[]")] else f" ({', '.join(outside[:3])} is outside every listed network)."))
    return None


def check(tenant_id: str | None, host: str, *, actor: str, where: str, addresses: list | None = None) -> str | None:
    """Decide for `host`, and audit a refusal in the workspace that asked. Returns the
    reason (None when it may be scanned). `addresses` is what the caller resolved; the
    collectors pass the ones they will dial."""
    if addresses is None:
        addresses = resolve_addresses(host)
    reason = decide(scope_for(tenant_id), host, addresses)
    if reason and tenant_id:
        from backend import store

        store.audit(tenant_id, actor or "scan", "scan.target_refused", {
            "target": str(host)[:253],
            "addresses": [str(address) for address in addresses[:5]],
            "where": where,
            "reason": reason[:300],
        })
    return reason
