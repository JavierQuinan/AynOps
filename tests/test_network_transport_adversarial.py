"""Additional offline adversarial tests for the experimental HTTP transport."""

import socket
from typing import ClassVar

import pytest

from utils import network_transport
from utils.network_safety import UnsafeDestination


class FakeSocket:
    def getpeername(self):
        return ("8.8.8.8", 443)


class FakeResponse:
    def __init__(self, status=200, location=None, body=b"ok"):
        self.status, self.location, self.body = status, location, body

    def getheaders(self):
        return [("Location", self.location)] if self.location else []

    def getheader(self, name):
        return self.location if name.lower() == "location" else None

    def read(self, limit):
        return self.body[:limit]


class FakeConnection:
    responses: ClassVar[list] = []
    connections: ClassVar[list] = []

    def __init__(self, host, port, timeout):
        self.host = host
        self.sock = None
        self.closed = False
        self.__class__.connections.append(self)

    def connect(self):
        self.sock = FakeSocket()

    def putrequest(self, *args, **kwargs):
        pass

    def putheader(self, *args):
        pass

    def endheaders(self):
        pass

    def getresponse(self):
        return self.__class__.responses.pop(0)

    def close(self):
        self.closed = True


def _resolver(host, port, **kwargs):
    if host == "internal.example":
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]


@pytest.fixture
def fake_transport(monkeypatch):
    FakeConnection.connections.clear()
    FakeConnection.responses = []
    monkeypatch.setattr(network_transport.http.client, "HTTPConnection", FakeConnection)
    return FakeConnection


def test_redirect_resolves_and_checks_next_destination(fake_transport):
    fake_transport.responses = [FakeResponse(302, "http://internal.example/")]
    with pytest.raises(UnsafeDestination):
        network_transport.fetch_public_http("http://example.com/", resolver=_resolver)
    assert len(fake_transport.connections) == 1
    assert fake_transport.connections[0].closed


def test_redirect_to_public_destination_reconnects(fake_transport):
    fake_transport.responses = [
        FakeResponse(302, "http://public.example/next"),
        FakeResponse(200, body=b"complete"),
    ]
    result = network_transport.fetch_public_http(
        "http://example.com/", resolver=_resolver
    )
    assert result.url == "http://public.example/next"
    assert result.body == b"complete"
    assert len(fake_transport.connections) == 2
    assert all(
        conn.host == "8.8.8.8" and conn.closed for conn in fake_transport.connections
    )


def test_response_body_limit_enforced(fake_transport):
    fake_transport.responses = [FakeResponse(200, body=b"x" * 9)]
    with pytest.raises(UnsafeDestination, match="body exceeds"):
        network_transport.fetch_public_http(
            "http://example.com/", resolver=_resolver, max_body_bytes=8
        )
    assert fake_transport.connections[0].closed


def test_redirect_budget_enforced(fake_transport):
    fake_transport.responses = [FakeResponse(302, "/again")]
    with pytest.raises(UnsafeDestination, match="Redirect limit"):
        network_transport.fetch_public_http(
            "http://example.com/", resolver=_resolver, max_redirects=0
        )
    assert fake_transport.connections[0].closed


def test_https_downgrade_redirect_rejected_before_second_connection(
    fake_transport, monkeypatch
):
    fake_transport.responses = [FakeResponse(302, "http://public.example/")]

    class Context:
        def wrap_socket(self, sock, *, server_hostname):
            return sock

    monkeypatch.setattr(network_transport.ssl, "create_default_context", Context)
    with pytest.raises(UnsafeDestination, match="downgrade"):
        network_transport.fetch_public_http("https://example.com/", resolver=_resolver)
    assert len(fake_transport.connections) == 1
    assert fake_transport.connections[0].closed


def test_dns_rebinding_on_redirect_is_rejected(fake_transport):
    fake_transport.responses = [FakeResponse(302, "/next")]
    resolutions = 0

    def changing_resolver(host, port, **kwargs):
        nonlocal resolutions
        resolutions += 1
        address = "8.8.8.8" if resolutions == 1 else "127.0.0.1"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]

    with pytest.raises(UnsafeDestination, match="Non-public"):
        network_transport.fetch_public_http(
            "http://example.com/", resolver=changing_resolver
        )
    assert resolutions == 2
    assert len(fake_transport.connections) == 1
    assert fake_transport.connections[0].closed


def test_tls_handshake_failure_closes_connection(fake_transport, monkeypatch):
    fake_transport.responses = [FakeResponse(200)]

    class RejectingContext:
        def wrap_socket(self, sock, *, server_hostname):
            assert server_hostname == "example.com"
            raise network_transport.ssl.SSLCertVerificationError("certificate rejected")

    monkeypatch.setattr(
        network_transport.ssl, "create_default_context", RejectingContext
    )
    with pytest.raises(network_transport.ssl.SSLCertVerificationError):
        network_transport.fetch_public_http("https://example.com/", resolver=_resolver)
    assert len(fake_transport.connections) == 1
    assert fake_transport.connections[0].closed


def test_response_at_exact_body_limit_is_accepted(fake_transport):
    fake_transport.responses = [FakeResponse(200, body=b"12345678")]
    result = network_transport.fetch_public_http(
        "http://example.com/", resolver=_resolver, max_body_bytes=8
    )
    assert result.body == b"12345678"
    assert fake_transport.connections[0].closed


def test_read_failure_still_closes_connection(fake_transport):
    class BrokenResponse(FakeResponse):
        def read(self, limit):
            raise OSError("connection interrupted")

    fake_transport.responses = [BrokenResponse()]
    with pytest.raises(OSError, match="interrupted"):
        network_transport.fetch_public_http("http://example.com/", resolver=_resolver)
    assert fake_transport.connections[0].closed


@pytest.mark.parametrize(
    ("timeout", "max_redirects", "max_body_bytes"),
    [
        (0, 5, 512_000),
        (-1, 5, 512_000),
        (10, -1, 512_000),
        (10, 5, -1),
    ],
)
def test_invalid_resource_limits_rejected_before_connection(
    fake_transport, timeout, max_redirects, max_body_bytes
):
    with pytest.raises(ValueError, match="resource limits"):
        network_transport.fetch_public_http(
            "http://example.com/",
            resolver=_resolver,
            timeout=timeout,
            max_redirects=max_redirects,
            max_body_bytes=max_body_bytes,
        )
    assert fake_transport.connections == []


def test_tls_context_receives_original_hostname(fake_transport, monkeypatch):
    fake_transport.responses = [FakeResponse(200)]
    seen = []

    class RecordingContext:
        def wrap_socket(self, sock, *, server_hostname):
            seen.append(server_hostname)
            return sock

    monkeypatch.setattr(
        network_transport.ssl, "create_default_context", RecordingContext
    )
    result = network_transport.fetch_public_http(
        "https://example.com/", resolver=_resolver
    )
    assert result.status_code == 200
    assert seen == ["example.com"]
    assert fake_transport.connections[0].host == "8.8.8.8"
    assert fake_transport.connections[0].closed


def test_excessive_response_header_count_is_rejected(fake_transport):
    class TooManyHeaders(FakeResponse):
        def getheaders(self):
            return [("X-Test", "ok")] * (network_transport.MAX_RESPONSE_HEADERS + 1)

    fake_transport.responses = [TooManyHeaders()]
    with pytest.raises(UnsafeDestination, match="header count"):
        network_transport.fetch_public_http("http://example.com/", resolver=_resolver)
    assert fake_transport.connections[0].closed


def test_excessive_response_header_bytes_are_rejected(fake_transport):
    class HugeHeader(FakeResponse):
        def getheaders(self):
            return [("X-Test", "x" * network_transport.MAX_RESPONSE_HEADER_BYTES)]

    fake_transport.responses = [HugeHeader()]
    with pytest.raises(UnsafeDestination, match="headers exceed"):
        network_transport.fetch_public_http("http://example.com/", resolver=_resolver)
    assert fake_transport.connections[0].closed
