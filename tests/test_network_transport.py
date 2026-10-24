"""Offline integration tests for experimental pinned-IP HTTP transport."""
import pytest

from utils import network_transport
from utils.network_safety import UnsafeDestination


class FakeSocket:
    def __init__(self, peer="8.8.8.8"):
        self.peer = peer

    def getpeername(self):
        return (self.peer, 443)


class FakeResponse:
    status = 200

    def getheaders(self):
        return [("Content-Type", "text/plain")]

    def getheader(self, name):
        return None

    def read(self, limit):
        return b"safe"


class FakeConnection:
    instances = []
    peer = "8.8.8.8"

    def __init__(self, host, port, timeout):
        self.host, self.port, self.timeout = host, port, timeout
        self.sock = None
        self.closed = False
        self.headers = []
        self.__class__.instances.append(self)

    def connect(self):
        self.sock = FakeSocket(self.peer)

    def putrequest(self, method, path, **kwargs):
        self.method, self.path = method, path

    def putheader(self, name, value):
        self.headers.append((name, value))

    def endheaders(self):
        pass

    def getresponse(self):
        return FakeResponse()

    def close(self):
        self.closed = True


def _resolver(host, port, **kwargs):
    import socket
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]


def test_http_connects_to_pinned_ip_not_hostname(monkeypatch):
    FakeConnection.instances.clear()
    monkeypatch.setattr(network_transport.http.client, "HTTPConnection", FakeConnection)
    result = network_transport.fetch_public_http(
        "http://example.com/path?q=1", resolver=_resolver
    )
    connection = FakeConnection.instances[-1]
    assert connection.host == "8.8.8.8"
    assert connection.method == "GET"
    assert connection.path == "/path?q=1"
    assert ("Host", "example.com") in connection.headers
    assert connection.closed
    assert result.body == b"safe"


def test_peer_mismatch_rejected_before_request(monkeypatch):
    FakeConnection.instances.clear()
    monkeypatch.setattr(network_transport.http.client, "HTTPConnection", FakeConnection)
    monkeypatch.setattr(FakeConnection, "peer", "127.0.0.1")
    try:
        with pytest.raises(UnsafeDestination):
            network_transport.fetch_public_http("http://example.com", resolver=_resolver)
        assert FakeConnection.instances[-1].closed
    finally:
        monkeypatch.setattr(FakeConnection, "peer", "8.8.8.8")


def test_https_uses_original_hostname_for_tls(monkeypatch):
    FakeConnection.instances.clear()
    monkeypatch.setattr(network_transport.http.client, "HTTPConnection", FakeConnection)
    observed = []

    class Context:
        def wrap_socket(self, sock, *, server_hostname):
            observed.append(server_hostname)
            return sock

    monkeypatch.setattr(network_transport.ssl, "create_default_context", lambda: Context())
    result = network_transport.fetch_public_http(
        "https://example.com/", resolver=_resolver
    )
    assert observed == ["example.com"]
    assert result.status_code == 200
