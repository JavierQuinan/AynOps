"""Offline security characterization for tech_stack_detect.

Baseline tests document actual HTTP behavior; xfail tests specify a future
network-safety contract. No real network calls are made.
"""
import socket

import pytest

from tools import techstack_tool


def test_baseline_http_client_follows_redirects(monkeypatch):
    """Characterize the existing redirect setting without network access."""
    observed = {}

    def fake_get(url, **kwargs):
        observed.update({"url": url, **kwargs})
        return object()

    monkeypatch.setattr(techstack_tool.requests, "get", fake_get)
    techstack_tool._fetch("https://example.com")

    assert observed["allow_redirects"] is True
    assert observed["stream"] is True


@pytest.mark.xfail(strict=True, reason="No destination-IP policy before requests.get yet")
@pytest.mark.parametrize("address", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "fd00::1", "::1"])
def test_reject_nonpublic_resolution_before_http(monkeypatch, address):
    """Desired future behavior; failure does NOT prove actual socket access."""
    calls = []

    def fake_getaddrinfo(host, port, *args, **kwargs):
        assert host == "example.com"
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        sockaddr = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
        return [(family, socket.SOCK_STREAM, 6, "", sockaddr)]

    def fake_get(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("HTTP must not be attempted for nonpublic destination")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(techstack_tool.requests, "get", fake_get)

    result = techstack_tool.tech_stack_detect("example.com")
    assert result["success"] is False
    assert calls == []


def test_baseline_rejects_malformed_domain_without_http(monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("No HTTP request expected")

    monkeypatch.setattr(techstack_tool.requests, "get", fail_if_called)
    assert techstack_tool.tech_stack_detect("http://127.0.0.1")["success"] is False
