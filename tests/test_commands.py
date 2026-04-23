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


# ---- Bare-IP BGP lookup (vendor-aware LPM dispatch) ----


def test_sixwind_os_bare_ipv4_uses_ip_lookup() -> None:
    # 6WIND ``prefix`` is exact-match; ``ip`` is the LPM/covering-route command.
    cmd = build_command("sixwind_os", QueryType.BGP_ROUTE, "1.1.1.1")
    assert cmd == "show bgp ipv4 ip 1.1.1.1"


def test_sixwind_os_bare_ipv6_uses_ip_lookup() -> None:
    cmd = build_command("sixwind_os", QueryType.BGP_ROUTE, "2001:4860:4860::8888")
    assert cmd == "show bgp ipv6 ip 2001:4860:4860::8888"


def test_sixwind_os_explicit_prefix_keeps_prefix_command() -> None:
    # Only bare host addresses route to the LPM override. Explicit prefixes
    # (including /32 and /128) use the standard ``prefix`` template.
    assert (
        build_command("sixwind_os", QueryType.BGP_ROUTE, "1.1.1.0/24")
        == "show bgp ipv4 prefix 1.1.1.0/24"
    )
    assert (
        build_command("sixwind_os", QueryType.BGP_ROUTE, "1.1.1.1/32")
        == "show bgp ipv4 prefix 1.1.1.1/32"
    )


def test_sixwind_os_bare_ip_ping_unaffected() -> None:
    # The LPM override only applies to BGP_ROUTE; ping/traceroute must still
    # use the standard ``cmd ping`` template with the bare target.
    assert build_command("sixwind_os", QueryType.PING, "1.1.1.1") == "cmd ping 1.1.1.1 count 6"


def test_junos_bare_ipv4_drops_exact_uses_best() -> None:
    # Junos `exact` forces strict prefix match (same class of bug as 6WIND
    # `prefix`). For a bare host address we drop `exact` and pin to `best`
    # so ECMP groups collapse to a single covering route.
    cmd = build_command("juniper_junos", QueryType.BGP_ROUTE, "1.1.1.1")
    assert cmd == "show route protocol bgp table inet.0 1.1.1.1 best detail"


def test_junos_bare_ipv6_drops_exact_uses_best() -> None:
    cmd = build_command("juniper_junos", QueryType.BGP_ROUTE, "2001:4860:4860::8888")
    assert cmd == "show route protocol bgp table inet6.0 2001:4860:4860::8888 best detail"


def test_junos_explicit_prefix_keeps_exact_detail() -> None:
    # Explicit prefixes continue to use `exact detail` — we want exact-match
    # semantics when the operator explicitly types a prefix.
    assert (
        build_command("juniper_junos", QueryType.BGP_ROUTE, "1.1.1.0/24")
        == "show route protocol bgp table inet.0 1.1.1.0/24 exact detail"
    )
    assert (
        build_command("juniper_junos", QueryType.BGP_ROUTE, "2001:db8::/32")
        == "show route protocol bgp table inet6.0 2001:db8::/32 exact detail"
    )


@pytest.mark.parametrize(
    ("platform", "expected"),
    [
        ("cisco_ios", "show bgp ipv4 unicast 1.1.1.1"),
        ("cisco_xe", "show bgp ipv4 unicast 1.1.1.1"),
        ("cisco_xr", "show bgp ipv4 unicast 1.1.1.1"),
        ("arista_eos", "show ip bgp 1.1.1.1"),
        ("huawei", "display bgp routing-table 1.1.1.1"),
    ],
)
def test_other_platforms_bare_ip_unchanged(platform: str, expected: str) -> None:
    # Platforms without an LPM override fall back to ``_COMMAND_TABLE``.
    # This test guards against accidental dispatch changes for vendors whose
    # standard BGP commands already do LPM on a bare IP (Cisco, Arista, Huawei).
    assert build_command(platform, QueryType.BGP_ROUTE, "1.1.1.1") == expected


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
