"""Transport-independent request planning for a pinned-IP HTTP client.

A RequestPlan is a security boundary between DNS policy and network I/O.
The future transport MUST connect to plan.address (not plan.hostname), use
plan.hostname for TLS SNI and certificate verification, and ignore ambient
proxy settings. Constructing a plan alone does not enforce these properties.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from utils.network_safety import (
    UnsafeDestination,
    resolve_public_addresses,
    validate_http_target,
    validate_public_address,
)


@dataclass(frozen=True)
class RequestPlan:
    url: str
    hostname: str
    port: int
    address: str
    tls: bool


def plan_public_request(url: str, *, resolver=None) -> RequestPlan:
    """Build an immutable request plan using a vetted resolved address."""
    hostname, port = validate_http_target(url)
    # Explicit literal-IP hosts are allowed only when globally routable.
    # DNS resolver remains responsible for rejecting mixed public/private sets.
    addresses = resolve_public_addresses(hostname, port, resolver=resolver)
    if not addresses:
        raise UnsafeDestination("No approved destination")
    address = validate_public_address(addresses[0])
    return RequestPlan(
        url=url,
        hostname=hostname,
        port=port,
        address=address,
        tls=urlsplit(url).scheme == "https",
    )


def verify_connection_peer(plan: RequestPlan, peer_address: str) -> None:
    """Defence-in-depth check for the actual connected socket peer.

    The transport MUST still pin the socket to plan.address before connecting.
    """
    peer = validate_public_address(peer_address)
    if peer != plan.address:
        raise UnsafeDestination("Connected peer differs from approved address")
