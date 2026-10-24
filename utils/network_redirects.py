"""Redirect decision policy; transport remains responsible for IP pinning."""
from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from utils.network_safety import UnsafeDestination, validate_http_target

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAX_REDIRECTS = 5


def next_redirect_url(current_url: str, status_code: int, location: str | None) -> str | None:
    """Return a validated next URL or None for non-redirect responses.

    Refuse HTTPS downgrade and reject credentials, control characters, and
    unsupported schemes. This only validates syntax, not resolved IPs.
    """
    validate_http_target(current_url)
    if status_code not in REDIRECT_STATUSES:
        return None
    if not location:
        raise UnsafeDestination("Redirect without Location header")
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in location):
        raise UnsafeDestination("Unsafe redirect Location")
    candidate = urljoin(current_url, location)
    validate_http_target(candidate)
    if urlsplit(current_url).scheme == "https" and urlsplit(candidate).scheme != "https":
        raise UnsafeDestination("HTTPS downgrade redirect is not permitted")
    return candidate


def redirect_limit_exceeded(hops: int, *, limit: int = MAX_REDIRECTS) -> bool:
    """Whether another redirect would exceed the configured hop budget."""
    if hops < 0 or limit < 0:
        raise ValueError("Redirect counts must be nonnegative")
    return hops >= limit
