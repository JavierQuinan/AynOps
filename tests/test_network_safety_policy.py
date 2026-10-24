"""Deterministic unit tests for the isolated destination-policy prototype."""

import socket

import pytest

from utils.network_safety import (
    UnsafeDestination,
    resolve_public_addresses,
    validate_public_address,
)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.2",
        "169.254.169.254",
        "0.0.0.0",
        "::1",
        "fd00::1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "not-an-ip",
    ],
)
def test_nonpublic_or_invalid_addresses_rejected(address):
    with pytest.raises(UnsafeDestination):
        validate_public_address(address)


@pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses_accepted(address):
    assert validate_public_address(address) == address


def test_mixed_dns_results_fail_closed():
    def resolver(host, port, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
        ]

    with pytest.raises(UnsafeDestination):
        resolve_public_addresses("example.com", 443, resolver=resolver)


def test_empty_dns_results_fail_closed():
    with pytest.raises(UnsafeDestination):
        resolve_public_addresses("example.com", 443, resolver=lambda *a, **kw: [])


def test_public_dns_results_deduplicated():
    def resolver(host, port, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port)),
        ]

    assert resolve_public_addresses("example.com", 443, resolver=resolver) == (
        "8.8.8.8",
    )
