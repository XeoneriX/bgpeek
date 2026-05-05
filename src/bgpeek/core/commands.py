"""Vendor-specific CLI command builders for network devices."""

from __future__ import annotations

import ipaddress
from typing import Literal

from bgpeek.models.query import QueryType

Family = Literal["v4", "v6"]

# Mapping: (platform, query_type, family) → command template.
# {target} is replaced with the actual IP/prefix at build time.
_COMMAND_TABLE: dict[tuple[str, QueryType, Family], str] = {
    # --- Juniper Junos ---
    (
        "juniper_junos",
        QueryType.BGP_ROUTE,
        "v4",
    ): "show route protocol bgp table inet.0 {target} exact detail",
    (
        "juniper_junos",
        QueryType.BGP_ROUTE,
        "v6",
    ): "show route protocol bgp table inet6.0 {target} exact detail",
    ("juniper_junos", QueryType.PING, "v4"): "ping {target} count 5",
    ("juniper_junos", QueryType.PING, "v6"): "ping inet6 {target} count 5",
    # NOTE: `traceroute monitor` may need expect_string in SSHClient.send_command
    # due to non-standard output format (interactive summary table).
    ("juniper_junos", QueryType.TRACEROUTE, "v4"): "traceroute monitor {target} count 5 summary",
    (
        "juniper_junos",
        QueryType.TRACEROUTE,
        "v6",
    ): "traceroute monitor inet6 {target} count 5 summary",
    # --- Cisco IOS / IOS-XE ---
    ("cisco_ios", QueryType.BGP_ROUTE, "v4"): "show bgp ipv4 unicast {target}",
    ("cisco_ios", QueryType.BGP_ROUTE, "v6"): "show bgp ipv6 unicast {target}",
    ("cisco_ios", QueryType.PING, "v4"): "ping {target} repeat 5",
    ("cisco_ios", QueryType.PING, "v6"): "ping ipv6 {target} repeat 5",
    ("cisco_ios", QueryType.TRACEROUTE, "v4"): "traceroute {target}",
    ("cisco_ios", QueryType.TRACEROUTE, "v6"): "traceroute ipv6 {target}",
    ("cisco_xe", QueryType.BGP_ROUTE, "v4"): "show bgp ipv4 unicast {target}",
    ("cisco_xe", QueryType.BGP_ROUTE, "v6"): "show bgp ipv6 unicast {target}",
    ("cisco_xe", QueryType.PING, "v4"): "ping {target} repeat 5",
    ("cisco_xe", QueryType.PING, "v6"): "ping ipv6 {target} repeat 5",
    ("cisco_xe", QueryType.TRACEROUTE, "v4"): "traceroute {target}",
    ("cisco_xe", QueryType.TRACEROUTE, "v6"): "traceroute ipv6 {target}",
    # --- Cisco IOS-XR ---
    ("cisco_xr", QueryType.BGP_ROUTE, "v4"): "show bgp ipv4 unicast {target}",
    ("cisco_xr", QueryType.BGP_ROUTE, "v6"): "show bgp ipv6 unicast {target}",
    ("cisco_xr", QueryType.PING, "v4"): "ping {target} count 5",
    ("cisco_xr", QueryType.PING, "v6"): "ping ipv6 {target} count 5",
    ("cisco_xr", QueryType.TRACEROUTE, "v4"): "traceroute {target}",
    ("cisco_xr", QueryType.TRACEROUTE, "v6"): "traceroute ipv6 {target}",
    # --- Arista EOS ---
    ("arista_eos", QueryType.BGP_ROUTE, "v4"): "show ip bgp {target}",
    ("arista_eos", QueryType.BGP_ROUTE, "v6"): "show ipv6 bgp {target}",
    ("arista_eos", QueryType.PING, "v4"): "ping ip {target} repeat 5",
    ("arista_eos", QueryType.PING, "v6"): "ping ipv6 {target} repeat 5",
    ("arista_eos", QueryType.TRACEROUTE, "v4"): "traceroute {target}",
    ("arista_eos", QueryType.TRACEROUTE, "v6"): "traceroute ipv6 {target}",
    # --- Huawei VRP ---
    ("huawei", QueryType.BGP_ROUTE, "v4"): "display bgp routing-table {target}",
    ("huawei", QueryType.BGP_ROUTE, "v6"): "display bgp ipv6 routing-table {target}",
    ("huawei", QueryType.PING, "v4"): "ping -c 5 {target}",
    ("huawei", QueryType.PING, "v6"): "ping ipv6 -c 5 {target}",
    ("huawei", QueryType.TRACEROUTE, "v4"): "tracert {target}",
    ("huawei", QueryType.TRACEROUTE, "v6"): "tracert ipv6 {target}",
    # --- 6WIND VSR ---
    ("sixwind_os", QueryType.BGP_ROUTE, "v4"): "show bgp ipv4 prefix {target}",
    ("sixwind_os", QueryType.BGP_ROUTE, "v6"): "show bgp ipv6 prefix {target}",
    ("sixwind_os", QueryType.PING, "v4"): "cmd ping {target} count 6",
    ("sixwind_os", QueryType.PING, "v6"): "cmd ping {target} count 6",
    ("sixwind_os", QueryType.TRACEROUTE, "v4"): "cmd traceroute {target}",
    ("sixwind_os", QueryType.TRACEROUTE, "v6"): "cmd traceroute {target}",
}

# Optional per-(platform, query_type) command flags. Each inner dict maps a
# logical flag name (e.g. "source", "no_resolve") to a suffix template. Suffix
# strings may use {value} for parameterised flags (source-IP) or be plain
# constants for boolean flags (no_resolve).
#
# Platforms or (platform, query_type) pairs absent from the dict simply have
# no optional flags — passing the flag is a no-op rather than an error, so
# 6WIND-style "doesn't support no-resolve" platforms degrade silently.
#
# Adding a new flag: append a key under the relevant (platform, query_type)
# entries. Adding a new platform's support: same. The flag is wired into
# `build_command` once via a kwarg; entries here are the per-platform truth.
_OPTIONAL_FLAGS: dict[tuple[str, QueryType], dict[str, str]] = {
    # --- Juniper Junos ---
    ("juniper_junos", QueryType.PING): {
        "source": " source {value}",
    },
    ("juniper_junos", QueryType.TRACEROUTE): {
        "source": " source {value}",
        # `traceroute monitor … no-resolve` confirmed working on the operator's
        # MX-series prod box — appended at the end of the existing template.
        "no_resolve": " no-resolve",
    },
    # --- Cisco IOS / IOS-XE ---
    ("cisco_ios", QueryType.PING): {"source": " source {value}"},
    ("cisco_ios", QueryType.TRACEROUTE): {"source": " source {value}"},
    ("cisco_xe", QueryType.PING): {"source": " source {value}"},
    ("cisco_xe", QueryType.TRACEROUTE): {"source": " source {value}"},
    # --- Cisco IOS-XR ---
    ("cisco_xr", QueryType.PING): {"source": " source {value}"},
    ("cisco_xr", QueryType.TRACEROUTE): {"source": " source {value}"},
    # --- Arista EOS ---
    ("arista_eos", QueryType.PING): {"source": " source {value}"},
    ("arista_eos", QueryType.TRACEROUTE): {"source": " source {value}"},
    # --- Huawei VRP ---
    ("huawei", QueryType.PING): {"source": " -a {value}"},
    ("huawei", QueryType.TRACEROUTE): {"source": " -a {value}"},
    # --- 6WIND VSR ---
    ("sixwind_os", QueryType.PING): {"source": " source {value}"},
    ("sixwind_os", QueryType.TRACEROUTE): {"source": " source {value}"},
}


class UnsupportedPlatformError(ValueError):
    """Raised when no command mapping exists for a platform + query type + family."""

    def __init__(self, platform: str, query_type: QueryType, family: Family) -> None:
        self.platform = platform
        self.query_type = query_type
        self.family = family
        super().__init__(f"no command defined for ({platform}, {query_type.value}, {family})")


def target_family(target: str) -> Family:
    """Detect the address family of a target IP/prefix string.

    Defaults to ``"v4"`` for inputs that don't parse as either family (which
    shouldn't happen after DNS resolution, but keeps the dispatcher total).
    """
    raw = target.strip().split("/", 1)[0]
    try:
        return "v6" if ipaddress.ip_address(raw).version == 6 else "v4"
    except ValueError:
        return "v4"


def build_command(
    platform: str,
    query_type: QueryType,
    target: str,
    *,
    source_ip: str | None = None,
    no_resolve: bool = False,
) -> str:
    """Return the CLI command string for a given platform, query type, and target.

    Picks IPv4- or IPv6-flavoured command syntax based on the target address
    family. Optional flags (``source_ip``, ``no_resolve``) are appended only
    when the (platform, query_type) pair declares support in
    ``_OPTIONAL_FLAGS``; unsupported flags degrade to no-ops rather than
    errors, so a deploy-wide knob like ``BGPEEK_TRACEROUTE_NO_RESOLVE`` works
    safely across a heterogeneous device fleet.
    """
    family = target_family(target)
    template = _COMMAND_TABLE.get((platform, query_type, family))
    if template is None:
        raise UnsupportedPlatformError(platform, query_type, family)
    cmd = template.format(target=target)
    flags = _OPTIONAL_FLAGS.get((platform, query_type), {})
    if source_ip and "source" in flags:
        cmd += flags["source"].format(value=source_ip)
    if no_resolve and "no_resolve" in flags:
        cmd += flags["no_resolve"]
    return cmd


def supported_optional_flags(platform: str, query_type: QueryType) -> set[str]:
    """Return the set of optional-flag names the given (platform, query_type) accepts.

    Used by capability-aware callers (UI checkbox state, audit fields) to
    distinguish "flag was honoured" from "flag was silently ignored".
    """
    return set(_OPTIONAL_FLAGS.get((platform, query_type), {}).keys())


def supported_platforms() -> list[str]:
    """Return sorted list of platforms that have at least one command mapping."""
    return sorted({platform for platform, _, _ in _COMMAND_TABLE})
