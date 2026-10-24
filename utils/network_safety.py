"""Pure destination policy primitives for the network-safety research branch.

This module does NOT prevent SSRF by itself: callers must enforce the policy
at connection time and on every redirect.
"""
from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable


class UnsafeDestination(ValueError):
    """The target is not permitted by the default public-network policy."""


def validate_public_address(address: str) -> str:
    """Return a canonical public address or fail closed."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError as exc:
        raise UnsafeDestination("Invalid IP address") from exc
    if not ip.is_global:
        raise UnsafeDestination("Non-public destination is not permitted")
    return str(ip)


def resolve_public_addresses(
    hostname: str,
    port: int,
    *,
    resolver: Callable = socket.getaddrinfo,
) -> tuple[str, ...]:
    """Resolve all A/AAAA answers; reject if ANY candidate is non-public.

    Resolving here is preflight only, not connection-time pinning.
    """
    try:
        records = resolver(hostname, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError) as exc:
        raise UnsafeDestination("Destination resolution failed") from exc

    addresses: list[str] = []
    for family, _, _, _, sockaddr in records:
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise UnsafeDestination("Unsupported address family")
        addresses.append(validate_public_address(sockaddr[0]))

    if not addresses:
        raise UnsafeDestination("No destination addresses resolved")
    return tuple(dict.fromkeys(addresses))
