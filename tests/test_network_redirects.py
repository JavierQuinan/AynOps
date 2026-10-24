"""Offline tests for the redirect decision policy."""

import pytest

from utils.network_redirects import next_redirect_url, redirect_limit_exceeded
from utils.network_safety import UnsafeDestination


@pytest.mark.parametrize(
    ("location", "expected"),
    [
        ("/next", "https://example.com/next"),
        ("../next", "https://example.com/next"),
        ("https://other.example/path", "https://other.example/path"),
    ],
)
def test_valid_redirects(location, expected):
    assert next_redirect_url("https://example.com/a/b", 302, location) == expected


@pytest.mark.parametrize(
    "location",
    [
        "http://example.com/",
        "file:///etc/passwd",
        "gopher://example.com/",
        "https://user:pass@example.com/",
        "https://example.com:0/",
        "https://example.com/\nadmin",
        "//127.0.0.1/\radmin",
    ],
)
def test_unsafe_redirects_rejected(location):
    with pytest.raises(UnsafeDestination):
        next_redirect_url("https://example.com/", 302, location)


def test_no_redirect_for_success_response():
    assert next_redirect_url("https://example.com/", 200, None) is None


def test_missing_location_fails_closed():
    with pytest.raises(UnsafeDestination):
        next_redirect_url("https://example.com/", 302, None)


def test_redirect_budget():
    assert redirect_limit_exceeded(4) is False
    assert redirect_limit_exceeded(5) is True
    with pytest.raises(ValueError):
        redirect_limit_exceeded(-1)
