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

# Overrides for BGP_ROUTE queries when the target is a bare host address
# (no CIDR mask). Some platforms expose a distinct "find the covering route
# for this IP" command that behaves as longest-prefix-match, while their
# standard prefix command treats the bare address as /32 or /128 exact and
# returns an empty result.
#
# Platforms absent from this table fall back to ``_COMMAND_TABLE`` — that is
# correct for Cisco, Arista, and Huawei, whose standard commands already
# perform LPM on a bare IP input.
_IP_LOOKUP_COMMANDS: dict[tuple[str, Family], str] = {
    # 6WIND VSR: ``prefix`` is exact-match, ``ip`` performs LPM.
    ("sixwind_os", "v4"): "show bgp ipv4 ip {target}",
    ("sixwind_os", "v6"): "show bgp ipv6 ip {target}",
    # Juniper Junos: dropping ``exact`` enables LPM; ``best`` pins the result
    # to a single winner (matters under ECMP) while keeping ``detail`` output
    # compatible with the existing Junos parser.
    ("juniper_junos", "v4"): "show route protocol bgp table inet.0 {target} best detail",
    ("juniper_junos", "v6"): "show route protocol bgp table inet6.0 {target} best detail",
}

# Per-platform source argument format for ping/traceroute. Same syntax for
# both families on every platform we currently support — Junos `inet6` /
# Cisco `ipv6` keywords already select the family on the command itself.
_SOURCE_FORMAT: dict[str, str] = {
    "juniper_junos": " source {source}",
    "cisco_ios": " source {source}",
    "cisco_xe": " source {source}",
    "cisco_xr": " source {source}",
    "arista_eos": " source {source}",
    "huawei": " -a {source}",
    "sixwind_os": " source {source}",
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


def _is_bare_host_address(target: str) -> bool:
    """True iff ``target`` is a single IP literal with no CIDR mask."""
    stripped = target.strip()
    if "/" in stripped:
        return False
    try:
        ipaddress.ip_address(stripped)
    except ValueError:
        return False
    return True


def build_command(
    platform: str, query_type: QueryType, target: str, *, source_ip: str | None = None
) -> str:
    """Return the CLI command string for a given platform, query type, and target.

    Picks IPv4- or IPv6-flavoured command syntax based on the target address
    family. Adds a per-platform ``source`` argument when ``source_ip`` is
    provided and the query type is ping or traceroute.

    For BGP_ROUTE queries against a bare host address, a platform-specific
    LPM override from ``_IP_LOOKUP_COMMANDS`` is preferred over the standard
    prefix-match template — relevant for vendors (e.g. 6WIND) whose prefix
    command is exact-match only.
    """
    family = target_family(target)
    template: str | None = None
    if query_type == QueryType.BGP_ROUTE and _is_bare_host_address(target):
        template = _IP_LOOKUP_COMMANDS.get((platform, family))
    if template is None:
        template = _COMMAND_TABLE.get((platform, query_type, family))
    if template is None:
        raise UnsupportedPlatformError(platform, query_type, family)
    cmd = template.format(target=target)
    if source_ip and query_type in (QueryType.PING, QueryType.TRACEROUTE):
        fmt = _SOURCE_FORMAT.get(platform)
        if fmt:
            cmd += fmt.format(source=source_ip)
    return cmd


def supported_platforms() -> list[str]:
    """Return sorted list of platforms that have at least one command mapping."""
    return sorted({platform for platform, _, _ in _COMMAND_TABLE})
