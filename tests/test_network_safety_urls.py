"""Offline tests for strict URL parsing and resolver injection."""

import socket

import pytest

from utils.network_safety import (
    UnsafeDestination,
    resolve_public_addresses,
    validate_http_target,
)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://example.com/path?q=1", ("example.com", 443)),
        ("http://example.com:8080/", ("example.com", 8080)),
        ("https://[2606:4700:4700::1111]/", ("2606:4700:4700::1111", 443)),
    ],
)
def test_valid_http_targets(url, expected):
    assert validate_http_target(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "gopher://example.com",
        "//example.com",
        "https://user:pass@example.com",
        "https://example.com:99999",
        "https://example.com:0",
        "https://example.com:abc",
        "https://[::1",
        "https://example.com/#fragment",
        "https://example.com/\nadmin",
        "https://example.com/\tadmin",
        "https://example.com/\radmin",
        "https://example.com/\x7fadmin",
        "https://",
    ],
)
def test_invalid_http_targets(url):
    with pytest.raises(UnsafeDestination):
        validate_http_target(url)


def test_default_resolver_is_bound_at_call_time(monkeypatch):
    observed = []

    def fake_getaddrinfo(host, port, **kwargs):
        observed.append((host, port))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert resolve_public_addresses("example.com", 443) == ("8.8.8.8",)
    assert observed == [("example.com", 443)]
