"""Input validation primitives for network query targets."""

from __future__ import annotations

from ipaddress import IPv4Network, IPv6Network, ip_network

BOGONS_V4: tuple[IPv4Network, ...] = (
    IPv4Network("0.0.0.0/8"),
    IPv4Network("10.0.0.0/8"),
    IPv4Network("100.64.0.0/10"),
    IPv4Network("127.0.0.0/8"),
    IPv4Network("169.254.0.0/16"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.0.0.0/24"),
    IPv4Network("192.0.2.0/24"),
    IPv4Network("192.168.0.0/16"),
    IPv4Network("198.18.0.0/15"),
    IPv4Network("198.51.100.0/24"),
    IPv4Network("203.0.113.0/24"),
    IPv4Network("224.0.0.0/4"),
    IPv4Network("240.0.0.0/4"),
    IPv4Network("255.255.255.255/32"),
)

BOGONS_V6: tuple[IPv6Network, ...] = (
    IPv6Network("::/128"),
    IPv6Network("::1/128"),
    IPv6Network("::ffff:0:0/96"),
    IPv6Network("64:ff9b::/96"),
    IPv6Network("100::/64"),
    IPv6Network("2001:db8::/32"),
    IPv6Network("fc00::/7"),
    IPv6Network("fe80::/10"),
    IPv6Network("ff00::/8"),
)

DEFAULT_MAX_PREFIX_V4: int = 24
DEFAULT_MAX_PREFIX_V6: int = 48


class TargetValidationError(ValueError):
    """Raised when a query target fails validation."""

    def __init__(self, reason: str, target: str) -> None:
        self.reason = reason
        self.target = target
        super().__init__(f"{reason}: {target}")


def parse_target(value: str) -> IPv4Network | IPv6Network:
    """Parse a string into an IPv4 or IPv6 network. Raises ValueError on bad input."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"empty or non-string target: {value!r}")
    return ip_network(value.strip(), strict=False)


def is_bogon(network: IPv4Network | IPv6Network) -> str | None:
    """Return matching bogon prefix string if `network` is inside any bogon, else None."""
    if isinstance(network, IPv4Network):
        for bogon_v4 in BOGONS_V4:
            if network.subnet_of(bogon_v4):
                return str(bogon_v4)
        return None
    for bogon_v6 in BOGONS_V6:
        if network.subnet_of(bogon_v6):
            return str(bogon_v6)
    return None


def is_default_route(network: IPv4Network | IPv6Network) -> bool:
    """Return True if `network` is 0.0.0.0/0 or ::/0."""
    return int(network.network_address) == 0 and network.prefixlen == 0


def is_unspecified_host(network: IPv4Network | IPv6Network) -> bool:
    """Return True if `network` is the explicit 0.0.0.0/32 or ::/128 host address."""
    if int(network.network_address) != 0:
        return False
    if isinstance(network, IPv4Network):
        return network.prefixlen == 32
    return network.prefixlen == 128


# Networks that have no useful meaning as a ping/traceroute destination and
# only generate noise on the router (or, worse, target the router itself or
# every host on a segment). Rejected for diagnostic queries regardless of
# the caller's role.
_DIAG_REJECT_V4: tuple[tuple[IPv4Network, str], ...] = (
    (IPv4Network("0.0.0.0/8"), "unspecified address (0.0.0.0/8)"),
    (IPv4Network("255.255.255.255/32"), "limited broadcast (255.255.255.255)"),
    (IPv4Network("224.0.0.0/4"), "IPv4 multicast (224.0.0.0/4)"),
    (IPv4Network("169.254.0.0/16"), "link-local (169.254.0.0/16)"),
)

_DIAG_REJECT_V6: tuple[tuple[IPv6Network, str], ...] = (
    (IPv6Network("::/128"), "IPv6 unspecified (::)"),
    (IPv6Network("ff00::/8"), "IPv6 multicast (ff00::/8)"),
    (IPv6Network("fe80::/10"), "IPv6 link-local (fe80::/10)"),
)


def diagnostic_target_rejection(network: IPv4Network | IPv6Network) -> str | None:
    """Return a rejection reason if `network` is unsuitable for ping/traceroute.

    Applies regardless of caller role: default route, unspecified, broadcast,
    multicast and link-local ranges are always meaningless as ping/trace
    destinations and only burn router resources.
    """
    if is_default_route(network):
        return "default route is not a valid ping/traceroute target"
    if isinstance(network, IPv4Network):
        for net, label in _DIAG_REJECT_V4:
            if network.subnet_of(net):
                return label
        return None
    for net6, label6 in _DIAG_REJECT_V6:
        if network.subnet_of(net6):
            return label6
    return None


def prefix_too_specific(
    network: IPv4Network | IPv6Network,
    max_v4: int = DEFAULT_MAX_PREFIX_V4,
    max_v6: int = DEFAULT_MAX_PREFIX_V6,
) -> bool:
    """True if the prefix length exceeds max_v4 (IPv4) or max_v6 (IPv6)."""
    if isinstance(network, IPv4Network):
        return network.prefixlen > max_v4
    return network.prefixlen > max_v6


def validate_target(
    value: str,
    *,
    max_v4: int = DEFAULT_MAX_PREFIX_V4,
    max_v6: int = DEFAULT_MAX_PREFIX_V6,
) -> IPv4Network | IPv6Network:
    """Parse and validate a query target. Raises TargetValidationError on failure."""
    try:
        network = parse_target(value)
    except ValueError as exc:
        raise TargetValidationError(f"parse error ({exc})", value) from exc

    if is_unspecified_host(network):
        raise TargetValidationError("unspecified host address", value)

    if is_default_route(network):
        raise TargetValidationError("default route is not a valid target", value)

    bogon = is_bogon(network)
    if bogon is not None:
        raise TargetValidationError(f"bogon prefix ({bogon})", value)

    if prefix_too_specific(network, max_v4=max_v4, max_v6=max_v6):
        raise TargetValidationError("prefix too specific", value)

    return network
