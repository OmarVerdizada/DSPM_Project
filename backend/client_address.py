"""The address a request came from (C4).

Behind a reverse proxy every request's peer is the proxy, so every audit row and every
per-address throttle would name the proxy - one attacker and every legitimate user would
share one counter. The proxy says who its client was in `X-Forwarded-For`, but anyone can
send that header, so it is believed only from a peer the operator has named as a proxy:
`DSPM_TRUSTED_PROXIES`, a comma-separated list of addresses and networks (CIDR).

From a trusted peer the header is read right to left - the right-most entry is the one
the nearest proxy added - skipping entries that are themselves trusted proxies, and the
first address that is not is the client. An entry that is not an address at all ends
the walk: the peer's own address is used rather than a value nobody vouched for. With
no trusted proxies configured the header is ignored entirely, which is the right
default for a console reached directly.
"""

from __future__ import annotations

import ipaddress
import os
from functools import lru_cache


@lru_cache(maxsize=8)
def _networks(setting: str) -> tuple:
    networks = []
    for item in setting.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return tuple(networks)


def trusted_proxies() -> tuple:
    return _networks(os.getenv("DSPM_TRUSTED_PROXIES", "").strip())


def _is_trusted(address: str, networks: tuple) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(parsed in network for network in networks)


def client_address(peer: str, forwarded_for: str = "") -> str:
    """The client's address for audit and throttling."""
    peer = str(peer or "")
    networks = trusted_proxies()
    if not networks or not _is_trusted(peer, networks) or not forwarded_for:
        return peer
    for hop in reversed([part.strip() for part in str(forwarded_for).split(",")]):
        try:
            ipaddress.ip_address(hop)
        except ValueError:
            return peer
        if not _is_trusted(hop, networks):
            return hop
    return peer


def request_address(request) -> str:
    peer = getattr(getattr(request, "client", None), "host", "") or ""
    headers = getattr(request, "headers", None) or {}
    return client_address(peer, headers.get("x-forwarded-for", ""))
