"""Experimental pinned-IP HTTP transport, isolated from MCP tools.

Each hop resolves and validates all DNS answers, then opens a socket to the
approved IP, not to the hostname. TLS retains the original hostname for SNI
and certificate verification. No ambient HTTP proxy is consulted.
"""

from __future__ import annotations

import http.client
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

from utils.network_redirects import next_redirect_url, redirect_limit_exceeded
from utils.network_request_plan import plan_public_request, verify_connection_peer
from utils.network_safety import UnsafeDestination

MAX_RESPONSE_BYTES = 512_000
MAX_RESPONSE_HEADERS = 100
MAX_RESPONSE_HEADER_BYTES = 16_384


@dataclass(frozen=True)
class SafeHTTPResult:
    url: str
    status_code: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


def fetch_public_http(
    url: str,
    *,
    resolver=None,
    timeout: float = 10.0,
    max_redirects: int = 5,
    max_body_bytes: int = MAX_RESPONSE_BYTES,
) -> SafeHTTPResult:
    """Fetch a public HTTP(S) resource using direct pinned-IP connections.

    This research implementation intentionally does not support proxies,
    cookies, HTTP/2, compression negotiation, or private network targets.
    """
    if timeout <= 0 or max_redirects < 0 or max_body_bytes < 0:
        raise ValueError("Invalid HTTP resource limits")
    current = url
    for hop in range(max_redirects + 1):
        plan = plan_public_request(current, resolver=resolver)
        parts = urlsplit(current)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        authority = parts.netloc
        connection = http.client.HTTPConnection(
            plan.address, plan.port, timeout=timeout
        )
        try:
            # Direct socket connect is pinned to the vetted numeric address.
            connection.connect()
            if connection.sock is None:
                raise UnsafeDestination("HTTP connection has no socket")
            verify_connection_peer(plan, connection.sock.getpeername()[0])
            if plan.tls:
                # HTTPSConnection normally derives SNI from its host. Since our
                # host is the pinned IP, explicitly wrap with the original DNS
                # hostname to preserve SNI and certificate hostname checks.
                context = ssl.create_default_context()
                connection.sock = context.wrap_socket(
                    connection.sock, server_hostname=plan.hostname
                )
            connection.putrequest(
                "GET", path, skip_host=True, skip_accept_encoding=True
            )
            connection.putheader("Host", authority)
            connection.putheader(
                "User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)"
            )
            connection.putheader("Accept-Encoding", "identity")
            connection.endheaders()
            response = connection.getresponse()
            headers = tuple(response.getheaders())
            if len(headers) > MAX_RESPONSE_HEADERS:
                raise UnsafeDestination("Response header count exceeds configured limit")
            header_bytes = sum(
                len(name.encode("utf-8")) + len(value.encode("utf-8")) + 4
                for name, value in headers
            )
            if header_bytes > MAX_RESPONSE_HEADER_BYTES:
                raise UnsafeDestination("Response headers exceed configured size limit")
            location = response.getheader("Location")
            next_url = next_redirect_url(current, response.status, location)
            if next_url is not None:
                if redirect_limit_exceeded(hop, limit=max_redirects):
                    raise UnsafeDestination("Redirect limit exceeded")
                current = next_url
                continue
            body = response.read(max_body_bytes + 1)
            if len(body) > max_body_bytes:
                raise UnsafeDestination("Response body exceeds configured limit")
            return SafeHTTPResult(
                url=current,
                status_code=response.status,
                headers=headers,
                body=body,
            )
        finally:
            connection.close()
    raise UnsafeDestination("Redirect limit exceeded")
