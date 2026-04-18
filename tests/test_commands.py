"""Tests for vendor-specific command builders."""

from __future__ import annotations

import pytest

from bgpeek.core.commands import (
    UnsupportedPlatformError,
    build_command,
    supported_platforms,
    target_family,
)
from bgpeek.models.query import QueryType


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("8.8.8.8", "v4"),
        ("8.8.8.0/24", "v4"),
        ("2001:4860:4860::8888", "v6"),
        ("2001:db8::/32", "v6"),
        (" 10.0.0.1 ", "v4"),
        ("not-an-ip", "v4"),  # default for unknown / hostname leftovers
    ],
)
def test_target_family(value: str, expected: str) -> None:
    assert target_family(value) == expected


def test_supported_platforms_present() -> None:
    plats = supported_platforms()
    assert "juniper_junos" in plats
    assert "huawei" in plats
    assert "arista_eos" in plats
    assert "sixwind_os" in plats


# --- Family-aware dispatch ----------------------------------------------------


def test_junos_bgp_v4_uses_inet0() -> None:
    cmd = build_command("juniper_junos", QueryType.BGP_ROUTE, "8.8.8.0/24")
    assert "inet.0" in cmd
    assert "inet6" not in cmd


def test_junos_bgp_v6_uses_inet6_0() -> None:
    cmd = build_command("juniper_junos", QueryType.BGP_ROUTE, "2001:4860::/32")
    assert "inet6.0" in cmd


def test_junos_ping_v6_uses_inet6_keyword() -> None:
    cmd = build_command("juniper_junos", QueryType.PING, "2001:4860:4860::8888")
    assert cmd.startswith("ping inet6 ")


def test_junos_traceroute_v6_uses_inet6_keyword() -> None:
    cmd = build_command("juniper_junos", QueryType.TRACEROUTE, "2001:4860:4860::8888")
    assert cmd.startswith("traceroute monitor inet6 ")


def test_cisco_ios_ping_v6_uses_ipv6_keyword() -> None:
    cmd = build_command("cisco_ios", QueryType.PING, "2001:db8::1")
    assert cmd.startswith("ping ipv6 ")


def test_arista_bgp_v6_uses_show_ipv6_bgp() -> None:
    cmd = build_command("arista_eos", QueryType.BGP_ROUTE, "2001:db8::/48")
    assert cmd.startswith("show ipv6 bgp")


def test_huawei_traceroute_v6_uses_ipv6_keyword() -> None:
    cmd = build_command("huawei", QueryType.TRACEROUTE, "2001:db8::1")
    assert cmd.startswith("tracert ipv6 ")


# ---- 6WIND VSR ----


def test_sixwind_os_bgp_v4_command() -> None:
    cmd = build_command("sixwind_os", QueryType.BGP_ROUTE, "8.8.8.0/24")
    assert cmd == "show bgp ipv4 prefix 8.8.8.0/24"


def test_sixwind_os_bgp_v6_command() -> None:
    cmd = build_command("sixwind_os", QueryType.BGP_ROUTE, "2001:db8::/48")
    assert cmd == "show bgp ipv6 prefix 2001:db8::/48"


# --- Source-IP injection ------------------------------------------------------


def test_source_appended_for_v4_ping_junos() -> None:
    cmd = build_command("juniper_junos", QueryType.PING, "8.8.8.8", source_ip="10.0.0.1")
    assert cmd.endswith(" source 10.0.0.1")


def test_source_appended_for_v6_ping_junos() -> None:
    cmd = build_command(
        "juniper_junos",
        QueryType.PING,
        "2001:4860:4860::8888",
        source_ip="2001:db8::1",
    )
    assert "inet6" in cmd
    assert cmd.endswith(" source 2001:db8::1")


def test_source_not_appended_for_bgp_route() -> None:
    cmd = build_command("juniper_junos", QueryType.BGP_ROUTE, "8.8.8.0/24", source_ip="10.0.0.1")
    assert "source" not in cmd


def test_huawei_source_uses_dash_a() -> None:
    cmd = build_command("huawei", QueryType.PING, "8.8.8.8", source_ip="10.0.0.1")
    assert cmd.endswith(" -a 10.0.0.1")


# ---- 6WIND VSR Source-IP Injection ----


def test_sixwind_os_source_uses_source_keyword() -> None:
    cmd = build_command("sixwind_os", QueryType.PING, "8.8.8.8", source_ip="10.0.0.1")
    assert cmd == "cmd ping 8.8.8.8 count 6 source 10.0.0.1"


# --- Errors -------------------------------------------------------------------


def test_unknown_platform_raises() -> None:
    with pytest.raises(UnsupportedPlatformError):
        build_command("nokia_sros", QueryType.PING, "8.8.8.8")
