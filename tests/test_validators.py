"""Tests for bgpeek.core.validators."""

from __future__ import annotations

from ipaddress import IPv4Network, IPv6Network

import pytest

from bgpeek.core.validators import (
    BOGONS_V4,
    BOGONS_V6,
    DEFAULT_MAX_PREFIX_V4,
    DEFAULT_MAX_PREFIX_V6,
    TargetValidationError,
    diagnostic_target_rejection,
    is_bogon,
    is_default_route,
    is_non_global_unicast_v6,
    is_unspecified_host,
    parse_target,
    prefix_too_specific,
    validate_target,
)


def test_constants_defaults() -> None:
    assert DEFAULT_MAX_PREFIX_V4 == 24
    assert DEFAULT_MAX_PREFIX_V6 == 48
    assert IPv4Network("10.0.0.0/8") in BOGONS_V4
    assert IPv6Network("fe80::/10") in BOGONS_V6


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("8.8.8.0/24", IPv4Network("8.8.8.0/24")),
        ("185.66.84.0/22", IPv4Network("185.66.84.0/22")),
        ("2001:4860:4860::/48", IPv6Network("2001:4860:4860::/48")),
        ("2001:4860::/32", IPv6Network("2001:4860::/32")),
    ],
)
def test_validate_target_passes(value: str, expected: IPv4Network | IPv6Network) -> None:
    assert validate_target(value) == expected


@pytest.mark.parametrize(
    ("value", "reason_part"),
    [
        ("0.0.0.0", "unspecified"),  # noqa: S104
        ("0.0.0.0/0", "default"),  # noqa: S104
        ("::/0", "default"),
        ("10.0.0.1", "bogon"),
        ("10.0.0.0/8", "bogon"),
        ("192.168.1.0/24", "bogon"),
        ("172.16.0.0/12", "bogon"),
        ("127.0.0.1", "bogon"),
        ("169.254.1.1", "bogon"),
        ("100.64.0.1", "bogon"),
        ("224.0.0.1", "bogon"),
        ("1.1.1.0/25", "too specific"),
        ("2001:db8::/32", "bogon"),
        ("fe80::/10", "bogon"),
        ("2001:4860::/64", "too specific"),
        ("not-an-ip", "parse"),
        ("", "parse"),
    ],
)
def test_validate_target_fails(value: str, reason_part: str) -> None:
    with pytest.raises(TargetValidationError) as excinfo:
        validate_target(value)
    assert reason_part in excinfo.value.reason
    assert excinfo.value.target == value
    assert reason_part in str(excinfo.value)


def test_target_validation_error_attributes() -> None:
    err = TargetValidationError("some reason", "1.2.3.4")
    assert err.reason == "some reason"
    assert err.target == "1.2.3.4"
    assert str(err) == "some reason: 1.2.3.4"


@pytest.mark.parametrize(
    ("value", "expected_bogon"),
    [
        (IPv4Network("10.0.0.0/24"), "10.0.0.0/8"),
        (IPv4Network("192.168.5.0/24"), "192.168.0.0/16"),
        (IPv4Network("127.0.0.0/8"), "127.0.0.0/8"),
        (IPv6Network("fe80::/64"), "fe80::/10"),
        (IPv6Network("2001:db8:1::/48"), "2001:db8::/32"),
    ],
)
def test_is_bogon_hits(value: IPv4Network | IPv6Network, expected_bogon: str) -> None:
    assert is_bogon(value) == expected_bogon


@pytest.mark.parametrize(
    "value",
    [
        IPv4Network("8.8.8.0/24"),
        IPv4Network("185.66.84.0/22"),
        IPv6Network("2001:4860::/32"),
    ],
)
def test_is_bogon_misses(value: IPv4Network | IPv6Network) -> None:
    assert is_bogon(value) is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (IPv4Network("8.8.8.0/24"), False),
        (IPv4Network("1.1.1.0/25"), True),
        (IPv4Network("8.8.8.8/32"), True),
        (IPv4Network("10.0.0.0/24"), False),
        (IPv6Network("2001:4860::/48"), False),
        (IPv6Network("2001:4860::/49"), True),
        (IPv6Network("2001:4860::/128"), True),
    ],
)
def test_prefix_too_specific(value: IPv4Network | IPv6Network, expected: bool) -> None:
    assert prefix_too_specific(value) is expected


def test_prefix_too_specific_custom_thresholds() -> None:
    assert prefix_too_specific(IPv4Network("8.8.8.0/24"), max_v4=23) is True
    assert prefix_too_specific(IPv6Network("2001::/48"), max_v6=32) is True
    assert prefix_too_specific(IPv4Network("8.8.0.0/16"), max_v4=16) is False


@pytest.mark.parametrize(
    "value",
    ["", "   ", "not-an-ip", "999.999.999.999", "1.2.3.4/40"],
)
def test_parse_target_raises(value: str) -> None:
    with pytest.raises(ValueError):  # noqa: PT011
        parse_target(value)


def test_parse_target_rejects_non_string() -> None:
    with pytest.raises(ValueError):  # noqa: PT011
        parse_target(123)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("8.8.8.0/24", IPv4Network("8.8.8.0/24")),
        (" 8.8.8.0/24 ", IPv4Network("8.8.8.0/24")),
        ("8.8.8.8", IPv4Network("8.8.8.8/32")),
        ("2001:db8::/32", IPv6Network("2001:db8::/32")),
    ],
)
def test_parse_target_ok(value: str, expected: IPv4Network | IPv6Network) -> None:
    assert parse_target(value) == expected


def test_is_default_route() -> None:
    assert is_default_route(IPv4Network("0.0.0.0/0")) is True
    assert is_default_route(IPv6Network("::/0")) is True
    assert is_default_route(IPv4Network("10.0.0.0/8")) is False
    assert is_default_route(IPv6Network("::/128")) is False


def test_is_unspecified_host() -> None:
    assert is_unspecified_host(IPv4Network("0.0.0.0/32")) is True
    assert is_unspecified_host(IPv6Network("::/128")) is True
    assert is_unspecified_host(IPv4Network("0.0.0.0/0")) is False
    assert is_unspecified_host(IPv6Network("::/0")) is False
    assert is_unspecified_host(IPv4Network("8.8.8.8/32")) is False
    assert is_unspecified_host(IPv6Network("2001::/128")) is False


@pytest.mark.parametrize(
    "value",
    [
        IPv6Network("::/1"),
        IPv6Network("::/28"),
        IPv6Network("fc00::/7"),
        IPv6Network("fe80::/10"),
        IPv6Network("ff00::/8"),
        IPv6Network("100::/64"),
        IPv6Network("1000::/4"),
    ],
)
def test_is_non_global_unicast_v6_blocks(value: IPv6Network) -> None:
    assert is_non_global_unicast_v6(value) is True


@pytest.mark.parametrize(
    "value",
    [
        IPv6Network("2001:4860::/32"),
        IPv6Network("2606:4700::/32"),
        IPv6Network("2a00::/12"),
        IPv6Network("2000::/3"),
    ],
)
def test_is_non_global_unicast_v6_allows(value: IPv6Network) -> None:
    assert is_non_global_unicast_v6(value) is False


@pytest.mark.parametrize(
    ("value", "reason_part"),
    [
        ("::/1", "Global Unicast"),
        ("::/28", "Global Unicast"),
        ("1000::/4", "Global Unicast"),
        ("4000::/2", "Global Unicast"),
    ],
)
def test_validate_target_rejects_non_gua_ipv6(value: str, reason_part: str) -> None:
    with pytest.raises(TargetValidationError) as excinfo:
        validate_target(value)
    assert reason_part in excinfo.value.reason


def test_validate_target_custom_thresholds() -> None:
    result = validate_target("8.8.8.0/25", max_v4=25)
    assert result == IPv4Network("8.8.8.0/25")
    with pytest.raises(TargetValidationError):
        validate_target("8.8.8.0/24", max_v4=23)


@pytest.mark.parametrize(
    "value",
    ["8.8.8.8", "1.1.1.1", "8.8.8.8/32", "2001:4860:4860::8888", "2606:4700:4700::1111/128"],
)
def test_validate_target_accepts_bare_host_by_default(value: str) -> None:
    """Bare host addresses (/32, /128) bypass prefix-too-specific by default.

    This is the LPM-lookup intent: the router resolves the bare address to its
    covering prefix. Output filter still enforces max_v4/max_v6 on the response.
    """
    result = validate_target(value)
    assert result.prefixlen in (32, 128)


@pytest.mark.parametrize(
    "value",
    ["8.8.8.8", "8.8.8.8/32", "2001:4860:4860::8888", "2001:4860:4860::8888/128"],
)
def test_validate_target_rejects_bare_host_when_flag_off(value: str) -> None:
    """When accept_bare_ip=False, host addresses are treated like any
    explicit prefix and rejected by the cutoff. Pre-v1.3.2 behavior."""
    with pytest.raises(TargetValidationError) as excinfo:
        validate_target(value, accept_bare_ip=False)
    assert "too specific" in excinfo.value.reason


def test_validate_target_flag_does_not_bypass_bogon_or_default() -> None:
    """accept_bare_ip only affects the prefix-length check —
    bogon/default/unspecified validation still applies."""
    with pytest.raises(TargetValidationError) as excinfo:
        validate_target("10.0.0.1", accept_bare_ip=True)
    assert "bogon" in excinfo.value.reason
    with pytest.raises(TargetValidationError) as excinfo:
        validate_target("0.0.0.0", accept_bare_ip=True)  # noqa: S104
    assert "unspecified" in excinfo.value.reason


def test_validate_target_flag_does_not_affect_explicit_prefixes() -> None:
    """An explicit /25 is still rejected even with the flag on — only bare
    hosts (/32, /128) are exempt from the cutoff."""
    with pytest.raises(TargetValidationError):
        validate_target("8.8.8.0/25", accept_bare_ip=True)


@pytest.mark.parametrize(
    ("value", "reason_part"),
    [
        ("0.0.0.0", "unspecified"),  # noqa: S104
        ("0.1.2.3", "unspecified"),
        ("0.0.0.0/8", "unspecified"),  # noqa: S104
        ("0.0.0.0/0", "default route"),  # noqa: S104
        ("255.255.255.255", "broadcast"),
        ("224.0.0.1", "multicast"),
        ("239.1.2.3", "multicast"),
        ("169.254.1.1", "link-local"),
        ("::", "unspecified"),
        ("::/0", "default route"),
        ("ff02::1", "multicast"),
        ("fe80::1", "link-local"),
        ("::/1", "Global Unicast"),
        ("100::1", "Global Unicast"),
    ],
)
def test_diagnostic_target_rejection_blocks(value: str, reason_part: str) -> None:
    net = parse_target(value)
    reason = diagnostic_target_rejection(net)
    assert reason is not None
    assert reason_part in reason


@pytest.mark.parametrize(
    "value",
    [
        "8.8.8.8",
        "1.1.1.1",
        "10.0.0.1",  # bogon, but ok for diagnostics from privileged role
        "2001:4860:4860::8888",
        "2606:4700:4700::1111",
    ],
)
def test_diagnostic_target_rejection_allows(value: str) -> None:
    assert diagnostic_target_rejection(parse_target(value)) is None
