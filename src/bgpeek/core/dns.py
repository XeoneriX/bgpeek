"""Async DNS resolution for query targets."""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field
from ipaddress import IPv4Address, ip_address, ip_network

import structlog

from bgpeek.config import settings

log = structlog.get_logger(__name__)


class DNSResolutionError(Exception):
    """Raised when a hostname cannot be resolved."""

    def __init__(self, hostname: str, reason: str) -> None:
        self.hostname = hostname
        self.reason = reason
        super().__init__(f"DNS resolution failed for {hostname!r}: {reason}")


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    """Result of resolving a query target string."""

    original: str
    resolved: str
    is_hostname: bool
    all_addresses: list[str] = field(default_factory=list)


def _is_ip_or_prefix(target: str) -> bool:
    """Return True if *target* is already an IP address or CIDR prefix."""
    try:
        ip_address(target)
        return True
    except ValueError:
        pass
    try:
        ip_network(target, strict=False)
        return True
    except ValueError:
        pass
    return False


async def resolve_target(target: str) -> ResolvedTarget:
    """Resolve a target string to IP address(es).

    If *target* is already an IP address or CIDR prefix, return it as-is.
    If *target* is a hostname, resolve via :func:`asyncio.get_event_loop().getaddrinfo`.
    """
    target = target.strip()
    if not target:
        raise DNSResolutionError(target, "empty target")

    if _is_ip_or_prefix(target):
        return ResolvedTarget(
            original=target,
            resolved=target,
            is_hostname=False,
            all_addresses=[],
        )

    # Hostname detected — check if DNS resolution is enabled.
    if not settings.dns_resolve_enabled:
        raise DNSResolutionError(
            target,
            "DNS resolution is disabled — enter an IP address",
        )

    # Resolve hostname.
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(
            target,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise DNSResolutionError(target, str(exc)) from exc

    if not infos:
        raise DNSResolutionError(target, "no addresses returned")

    # Deduplicate while preserving order.
    seen: set[str] = set()
    all_addresses: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.add(addr)
            all_addresses.append(addr)

    # Prefer IPv4 if available, otherwise first result.
    resolved = all_addresses[0]
    for addr in all_addresses:
        try:
            if isinstance(ip_address(addr), IPv4Address):
                resolved = addr
                break
        except ValueError:
            continue

    log.info(
        "dns_resolved",
        hostname=target,
        resolved=resolved,
        all_addresses=all_addresses,
    )

    return ResolvedTarget(
        original=target,
        resolved=resolved,
        is_hostname=True,
        all_addresses=all_addresses,
    )
