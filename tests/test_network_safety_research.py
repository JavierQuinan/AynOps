"""Security research: fail-closed destination checks (expected to fail on baseline).

These tests do not perform any external network I/O. They document desired
behavior, not a confirmed remotely exploitable vulnerability.
"""
import socket

from tools import techstack_tool


def test_tech_stack_rejects_domain_resolving_to_loopback(monkeypatch):
    """A syntactically valid FQDN must not authorize loopback connections."""
    calls = []

    def fake_getaddrinfo(host, port, *args, **kwargs):
        assert host == "example.com"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    def unexpected_http_request(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("HTTP request attempted before destination policy check")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(techstack_tool.requests, "get", unexpected_http_request)

    result = techstack_tool.tech_stack_detect("example.com")

    assert result["success"] is False
    assert calls == [], "Destination must be rejected before any HTTP request"


def test_tech_stack_rejects_private_ipv6_resolution(monkeypatch):
    """Private IPv6 results must be subject to the same destination policy."""
    calls = []

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fd00::1", port, 0, 0))]

    def unexpected_http_request(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("HTTP request attempted before destination policy check")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(techstack_tool.requests, "get", unexpected_http_request)

    result = techstack_tool.tech_stack_detect("example.com")

    assert result["success"] is False
    assert calls == [], "Private IPv6 destination must be rejected before HTTP"
