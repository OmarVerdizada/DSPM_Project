"""M12 (roadmap 1.4): DNS-rebind-safe scan-target resolution.

The API validates a scan target's resolved IP up front, but the collectors used to
connect by *hostname* and let the SMB/WinRM library re-resolve it. A hostile,
TTL-0 name can answer with an allowed (public) IP during validation and then flip
to loopback / link-local / a private host at connect time - classic DNS rebinding,
turning the scanner into an SSRF primitive against the collector's own host.

The fix: resolve the name ONCE, validate EVERY resolved address, and hand back a
single pinned IP the caller connects to directly - so the address that was
validated is exactly the address that is dialed, with no second lookup.

Whether an address is in scope is the workspace's decision (C5, backend/target_scope):
its own list of networks and host names, checked here on the addresses about to be
dialed and at the API before a scan is accepted, so the rule cannot drift. What is
never a scan target - loopback, link-local, metadata - is refused here whatever a list
says.
"""
from __future__ import annotations

import ipaddress
import socket


class TargetNotAllowed(Exception):
    """A scan target could not be resolved, or resolved to a disallowed address."""


# Cloud instance-metadata endpoints - never a legitimate scan target (SSRF sink).
_METADATA_IPS = {"169.254.169.254", "fd00:ec2::254"}


def ip_disallowed_reason(ip: ipaddress._BaseAddress, allow_private: bool) -> str | None:
    """Return why `ip` must not be a scan target, or None if it is permissible.
    Loopback / link-local / multicast / reserved / unspecified / cloud-metadata are
    ALWAYS refused (even when private targets are allowed)."""
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return "loopback / link-local / multicast / reserved / unspecified address"
    if str(ip) in _METADATA_IPS:
        return "cloud metadata address"
    if ip.is_private and not allow_private:
        return "private-network target (disabled by configuration)"
    return None


def resolve_addresses(host: str) -> list[ipaddress._BaseAddress]:
    """Resolve `host` to IP addresses. An IP literal returns itself. Returns [] on
    resolution failure."""
    host = (host or "").strip().strip("[]")
    if not host:
        return []
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    found: list[ipaddress._BaseAddress] = []
    try:
        for family, _type, _proto, _canon, sockaddr in socket.getaddrinfo(host, None):
            if family in (socket.AF_INET, socket.AF_INET6):
                try:
                    found.append(ipaddress.ip_address(sockaddr[0]))
                except ValueError:
                    continue
    except socket.gaierror:
        return []
    return found


def resolve_and_pin(host: str, allow_private: bool | None = None, *, tenant_id: str | None = None) -> str:
    """Resolve `host` once, refuse if ANY resolved address is disallowed, and return
    a single pinned IP string (IPv4 preferred) for the caller to connect to. Raises
    TargetNotAllowed on resolution failure or a disallowed address.

    `tenant_id` names the workspace whose scan targets decide (C5); a refusal is
    audited there and nothing is dialed. `allow_private` is an explicit address policy
    instead of a workspace's, for callers that have one.

    Connecting to the returned IP - rather than re-resolving `host` - is what closes
    the DNS-rebind window: the validated address is the dialed address."""
    addresses = resolve_addresses(host)
    if not addresses:
        raise TargetNotAllowed(f"could not resolve scan target {host!r}")
    if allow_private is not None:
        for ip in addresses:
            reason = ip_disallowed_reason(ip, allow_private)
            if reason:
                raise TargetNotAllowed(
                    f"scan target {host!r} resolved to a disallowed address {ip} ({reason})"
                )
    else:
        from backend.target_scope import check

        reason = check(tenant_id, host, actor="scan", where="connect", addresses=addresses)
        if reason:
            raise TargetNotAllowed(reason)
    for ip in addresses:
        if ip.version == 4:
            return str(ip)
    return str(addresses[0])
