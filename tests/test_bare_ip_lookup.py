"""Tests for bare-IP LPM lookup: accepting host addresses as BGP targets."""

from __future__ import annotations

from ipaddress import IPv4Network, IPv6Network

import pytest

from bgpeek.config import Settings
from bgpeek.core.output_filter import has_any_prefix
from bgpeek.core.validators import (
    TargetValidationError,
    is_host_lookup,
    validate_target,
)
from bgpeek.models.query import QueryResponse, QueryType


def test_setting_accept_bare_ip_lookup_defaults_true() -> None:
    assert Settings().accept_bare_ip_lookup is True


def test_is_host_lookup_v4() -> None:
    assert is_host_lookup(IPv4Network("8.8.8.8/32")) is True
    assert is_host_lookup(IPv4Network("8.8.8.0/24")) is False
    assert is_host_lookup(IPv4Network("8.8.8.0/31")) is False


def test_is_host_lookup_v6() -> None:
    assert is_host_lookup(IPv6Network("2001:4860::1/128")) is True
    assert is_host_lookup(IPv6Network("2001:4860::/48")) is False
    assert is_host_lookup(IPv6Network("2001:4860::/127")) is False


def test_bare_ipv4_accepted_at_default_cutoff() -> None:
    """Default max_v4=24 would reject /32 without the bypass — bare IP should pass."""
    result = validate_target("8.8.8.8")
    assert result == IPv4Network("8.8.8.8/32")


def test_bare_ipv6_accepted_at_default_cutoff() -> None:
    result = validate_target("2001:4860:4860::8888")
    assert result == IPv6Network("2001:4860:4860::8888/128")


def test_bare_ip_accepted_with_custom_cutoffs() -> None:
    """Even with an unusual cutoff like /16, bare /32 host still passes."""
    result = validate_target("8.8.8.8", max_v4=16)
    assert result == IPv4Network("8.8.8.8/32")


def test_explicit_slash_32_treated_as_host_lookup() -> None:
    """`8.8.8.8/32` is semantically the same as `8.8.8.8` — both LPM intents."""
    assert validate_target("8.8.8.8/32") == IPv4Network("8.8.8.8/32")


def test_flag_off_restores_strict_rejection() -> None:
    with pytest.raises(TargetValidationError) as excinfo:
        validate_target("8.8.8.8", accept_bare_ip_lookup=False)
    assert "too specific" in excinfo.value.reason


def test_explicit_more_specific_prefix_still_rejected() -> None:
    """Only bare hosts are exempt — explicit /25 stays rejected."""
    with pytest.raises(TargetValidationError):
        validate_target("8.8.8.0/25")


def test_has_any_prefix_detects_ipv4_and_ipv6() -> None:
    assert has_any_prefix("routing table for 8.8.8.0/24 ...") is True
    assert has_any_prefix("2001:4860::/32   next-hop ...") is True
    assert has_any_prefix("no routes here") is False
    assert has_any_prefix("") is False


def test_query_response_lpm_hidden_default_false() -> None:
    r = QueryResponse(
        device_name="rt1",
        query_type=QueryType.BGP_ROUTE,
        target="8.8.8.8",
        command="show route 8.8.8.8",
        raw_output="",
        filtered_output="",
        runtime_ms=10,
    )
    assert r.lpm_hidden is False


def test_query_response_lpm_hidden_can_be_set() -> None:
    r = QueryResponse(
        device_name="rt1",
        query_type=QueryType.BGP_ROUTE,
        target="8.8.8.8",
        command="show route 8.8.8.8",
        raw_output="",
        filtered_output="",
        runtime_ms=10,
        lpm_hidden=True,
    )
    assert r.lpm_hidden is True
