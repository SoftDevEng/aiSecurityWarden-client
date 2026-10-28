"""Client-address allowlists for credentials. Standard library only; shared by server and client."""

from __future__ import annotations

import ipaddress
from typing import Iterable

MAX_ALLOWED_IPS = 32


def normalize_allowed_ips(values: Iterable[str]) -> list[str]:
    """Validate addresses / CIDR ranges and return them in canonical CIDR form.

    Raises ValueError on anything that is not an exact address or network
    (``192.168.1.12/24`` is rejected rather than silently widened to the /24).
    """
    out: list[str] = []
    for v in values:
        if not isinstance(v, str):
            raise ValueError("invalid address")
        try:
            net = str(ipaddress.ip_network(v.strip(), strict=True))
        except ValueError:
            raise ValueError(f"invalid address or CIDR range: {v!r}") from None
        if net not in out:
            out.append(net)
    if not out:
        raise ValueError("empty address list")
    if len(out) > MAX_ALLOWED_IPS:
        raise ValueError(f"at most {MAX_ALLOWED_IPS} addresses per credential")
    return out


def parse_peer(value: str | None) -> str | None:
    """Canonical IP from ``1.2.3.4``, ``1.2.3.4:5678``, ``::1`` or ``[::1]:5678``; None if not an IP."""
    s = (value or "").strip()
    if s.startswith("["):
        s = s[1:].split("]", 1)[0]
    elif s.count(":") == 1:  # IPv4 with a port (IIS/ARR appends one by default)
        s = s.split(":", 1)[0]
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return None
    mapped = getattr(ip, "ipv4_mapped", None)
    return str(mapped or ip)


def ip_allowed(ip: str | None, allowed: Iterable[str]) -> bool:
    """True if ``ip`` falls inside any of the canonical networks. Unparseable addresses never match."""
    peer = parse_peer(ip)
    if peer is None:
        return False
    addr = ipaddress.ip_address(peer)
    return any(addr in ipaddress.ip_network(n) for n in allowed)
