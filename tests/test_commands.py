"""Tests for vendor-specific command builders."""

from __future__ import annotations

import pytest

from bgpeek.core.commands import (
    UnsupportedPlatformError,
    build_command,
    supported_optional_flags,
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


# --- Optional flags: no_resolve -----------------------------------------------


def test_junos_traceroute_v4_no_resolve_appended() -> None:
    cmd = build_command("juniper_junos", QueryType.TRACEROUTE, "8.8.8.8", no_resolve=True)
    assert cmd.endswith(" no-resolve")
    assert cmd.startswith("traceroute monitor 8.8.8.8 ")


def test_junos_traceroute_v6_no_resolve_appended() -> None:
    cmd = build_command(
        "juniper_junos", QueryType.TRACEROUTE, "2001:4860:4860::8888", no_resolve=True
    )
    assert "inet6" in cmd
    assert cmd.endswith(" no-resolve")


def test_no_resolve_with_source_ip_both_appended() -> None:
    cmd = build_command(
        "juniper_junos",
        QueryType.TRACEROUTE,
        "8.8.8.8",
        source_ip="10.0.0.1",
        no_resolve=True,
    )
    # Both flags present; order is source then no-resolve (insertion order in
    # build_command), but the test asserts containment, not strict order, to
    # leave room for future flag-ordering tweaks without breaking.
    assert " source 10.0.0.1" in cmd
    assert " no-resolve" in cmd


def test_no_resolve_false_does_not_append() -> None:
    cmd = build_command("juniper_junos", QueryType.TRACEROUTE, "8.8.8.8", no_resolve=False)
    assert "no-resolve" not in cmd


def test_no_resolve_default_is_off() -> None:
    """Belt-and-braces: omitting the kwarg must equal no_resolve=False."""
    cmd = build_command("juniper_junos", QueryType.TRACEROUTE, "8.8.8.8")
    assert "no-resolve" not in cmd


def test_no_resolve_silently_ignored_on_unsupported_platform() -> None:
    """Cisco IOS doesn't have a no_resolve entry yet — flag must be a no-op,
    not raise. The deploy-wide env knob has to work across mixed fleets."""
    cmd = build_command("cisco_ios", QueryType.TRACEROUTE, "8.8.8.8", no_resolve=True)
    assert cmd == "traceroute 8.8.8.8"


def test_no_resolve_ignored_on_bgp_route() -> None:
    """no_resolve only meaningful for traceroute; BGP_ROUTE entries don't
    declare it, so the flag is a no-op there too."""
    cmd = build_command("juniper_junos", QueryType.BGP_ROUTE, "8.8.8.0/24", no_resolve=True)
    assert "no-resolve" not in cmd


# --- Capability introspection -------------------------------------------------


def test_supported_optional_flags_junos_traceroute() -> None:
    flags = supported_optional_flags("juniper_junos", QueryType.TRACEROUTE)
    assert flags == {"source", "no_resolve"}


def test_supported_optional_flags_junos_ping_lacks_no_resolve() -> None:
    """ping no-resolve is a separate Junos flag — not yet wired, so capability
    must reflect that to keep UI/audit honest."""
    flags = supported_optional_flags("juniper_junos", QueryType.PING)
    assert "source" in flags
    assert "no_resolve" not in flags


def test_supported_optional_flags_unknown_pair_returns_empty() -> None:
    flags = supported_optional_flags("nokia_sros", QueryType.PING)
    assert flags == set()


# --- Errors -------------------------------------------------------------------


def test_unknown_platform_raises() -> None:
    with pytest.raises(UnsupportedPlatformError):
        build_command("nokia_sros", QueryType.PING, "8.8.8.8")
