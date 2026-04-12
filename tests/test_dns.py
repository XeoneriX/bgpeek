"""Tests for bgpeek.core.dns."""

from __future__ import annotations

import socket
from unittest.mock import AsyncMock, patch

import pytest

from bgpeek.core.dns import DNSResolutionError, ResolvedTarget, resolve_target


@pytest.mark.asyncio
async def test_resolve_ip_address_passthrough() -> None:
    result = await resolve_target("8.8.8.8")
    assert result == ResolvedTarget(
        original="8.8.8.8",
        resolved="8.8.8.8",
        is_hostname=False,
        all_addresses=[],
    )


@pytest.mark.asyncio
async def test_resolve_prefix_passthrough() -> None:
    result = await resolve_target("185.66.84.0/22")
    assert result == ResolvedTarget(
        original="185.66.84.0/22",
        resolved="185.66.84.0/22",
        is_hostname=False,
        all_addresses=[],
    )


@pytest.mark.asyncio
async def test_resolve_ipv6_passthrough() -> None:
    result = await resolve_target("2001:4860:4860::8888")
    assert result == ResolvedTarget(
        original="2001:4860:4860::8888",
        resolved="2001:4860:4860::8888",
        is_hostname=False,
        all_addresses=[],
    )


@pytest.mark.asyncio
async def test_resolve_ipv6_prefix_passthrough() -> None:
    result = await resolve_target("2001:db0::/32")
    assert result == ResolvedTarget(
        original="2001:db0::/32",
        resolved="2001:db0::/32",
        is_hostname=False,
        all_addresses=[],
    )


@pytest.mark.asyncio
async def test_resolve_hostname_success() -> None:
    fake_infos = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        (
            socket.AF_INET6,
            socket.SOCK_STREAM,
            6,
            "",
            ("2606:2800:220:1:248:1893:25c8:1946", 0, 0, 0),
        ),
    ]
    with patch("bgpeek.core.dns.asyncio.get_running_loop") as mock_loop:
        loop = AsyncMock()
        loop.getaddrinfo.return_value = fake_infos
        mock_loop.return_value = loop

        result = await resolve_target("example.com")

    assert result.original == "example.com"
    assert result.resolved == "93.184.216.34"
    assert result.is_hostname is True
    assert "93.184.216.34" in result.all_addresses
    assert "2606:2800:220:1:248:1893:25c8:1946" in result.all_addresses


@pytest.mark.asyncio
async def test_resolve_hostname_ipv6_only() -> None:
    fake_infos = [
        (
            socket.AF_INET6,
            socket.SOCK_STREAM,
            6,
            "",
            ("2606:2800:220:1:248:1893:25c8:1946", 0, 0, 0),
        ),
    ]
    with patch("bgpeek.core.dns.asyncio.get_running_loop") as mock_loop:
        loop = AsyncMock()
        loop.getaddrinfo.return_value = fake_infos
        mock_loop.return_value = loop

        result = await resolve_target("ipv6only.example.com")

    assert result.resolved == "2606:2800:220:1:248:1893:25c8:1946"
    assert result.is_hostname is True


@pytest.mark.asyncio
async def test_resolve_unresolvable_hostname() -> None:
    with patch("bgpeek.core.dns.asyncio.get_running_loop") as mock_loop:
        loop = AsyncMock()
        loop.getaddrinfo.side_effect = socket.gaierror("Name or service not known")
        mock_loop.return_value = loop

        with pytest.raises(DNSResolutionError, match="Name or service not known"):
            await resolve_target("nonexistent.invalid")


@pytest.mark.asyncio
async def test_resolve_empty_target() -> None:
    with pytest.raises(DNSResolutionError, match="empty target"):
        await resolve_target("")


@pytest.mark.asyncio
async def test_resolve_whitespace_target() -> None:
    with pytest.raises(DNSResolutionError, match="empty target"):
        await resolve_target("   ")


@pytest.mark.asyncio
async def test_resolve_deduplicates_addresses() -> None:
    fake_infos = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.35", 0)),
    ]
    with patch("bgpeek.core.dns.asyncio.get_running_loop") as mock_loop:
        loop = AsyncMock()
        loop.getaddrinfo.return_value = fake_infos
        mock_loop.return_value = loop

        result = await resolve_target("multi.example.com")

    assert result.all_addresses == ["93.184.216.34", "93.184.216.35"]


@pytest.mark.asyncio
async def test_resolve_no_results() -> None:
    with patch("bgpeek.core.dns.asyncio.get_running_loop") as mock_loop:
        loop = AsyncMock()
        loop.getaddrinfo.return_value = []
        mock_loop.return_value = loop

        with pytest.raises(DNSResolutionError, match="no addresses returned"):
            await resolve_target("empty.example.com")
