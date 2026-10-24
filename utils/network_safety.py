"""URL and address policy primitives for network-safety research.

This is NOT a complete SSRF mitigation. The HTTP transport must connect to
an approved IP without resolving the hostname again, validate each redirect,
and define an explicit proxy policy.
"""
from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from urllib.parse import urlsplit


class UnsafeDestination(ValueError):
    """The destination violates the default public-network policy."""


def validate_public_address(address: str) -> str:
    """Canonicalize a globally routable address or reject it."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError as exc:
        raise UnsafeDestination("Invalid IP address") from exc
    if not ip.is_global:
        raise UnsafeDestination("Non-public destination is not permitted")
    return str(ip)


def validate_http_target(url: str) -> tuple[str, int]:
    """Return hostname and port for a strictly parsed HTTP(S) URL."""
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in url):
        raise UnsafeDestination("Invalid whitespace or control character")
    try:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise UnsafeDestination("Unsupported URL scheme")
        if not parts.netloc or not parts.hostname:
            raise UnsafeDestination("Missing destination hostname")
        if parts.username is not None or parts.password is not None:
            raise UnsafeDestination("URL credentials are not permitted")
        if parts.fragment:
            raise UnsafeDestination("URL fragments are not permitted")
        hostname = parts.hostname
        port = parts.port
        if port is None:
            port = 443 if parts.scheme == "https" else 80
        if not 1 <= port <= 65535:
            raise UnsafeDestination("Invalid destination port")
        return hostname, port
    except ValueError as exc:
        raise UnsafeDestination("Invalid HTTP destination URL") from exc


def resolve_public_addresses(
    hostname: str,
    port: int,
    *,
    resolver: Callable | None = None,
) -> tuple[str, ...]:
    """Reject any non-public A/AAAA answer (preflight only, not IP pinning)."""
    lookup = resolver if resolver is not None else socket.getaddrinfo
    try:
        records = lookup(hostname, port, type=socket.SOCK_STREAM)
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
