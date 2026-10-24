"""No-network tests for the connection-pinning contract."""
import socket

import pytest

from utils.network_request_plan import (
    plan_public_request,
    verify_connection_peer,
)
from utils.network_safety import UnsafeDestination


def _dns(*addresses):
    def resolver(host, port, **kwargs):
        result = []
        for address in addresses:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            sockaddr = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
            result.append((family, socket.SOCK_STREAM, 6, "", sockaddr))
        return result
    return resolver


def test_plan_keeps_original_tls_hostname_and_pins_public_ip():
    plan = plan_public_request(
        "https://example.com/path", resolver=_dns("8.8.8.8")
    )
    assert plan.address == "8.8.8.8"
    assert plan.hostname == "example.com"
    assert plan.port == 443
    assert plan.tls is True
    assert plan.url == "https://example.com/path"
    verify_connection_peer(plan, "8.8.8.8")


def test_dns_rebinding_peer_mismatch_rejected():
    plan = plan_public_request("https://example.com", resolver=_dns("8.8.8.8"))
    with pytest.raises(UnsafeDestination):
        verify_connection_peer(plan, "127.0.0.1")
    with pytest.raises(UnsafeDestination):
        verify_connection_peer(plan, "1.1.1.1")


def test_mixed_dns_answer_rejected_before_plan():
    with pytest.raises(UnsafeDestination):
        plan_public_request(
            "https://example.com",
            resolver=_dns("8.8.8.8", "10.0.0.2"),
        )


def test_ipv6_public_plan():
    plan = plan_public_request(
        "https://example.com", resolver=_dns("2606:4700:4700::1111")
    )
    assert plan.address == "2606:4700:4700::1111"
    verify_connection_peer(plan, plan.address)
