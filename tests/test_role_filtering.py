"""Tests for per-role output filtering: public sees filtered, noc/admin see everything."""

from __future__ import annotations

from ipaddress import IPv4Address
from unittest.mock import AsyncMock, patch

import asyncpg
import pytest

from bgpeek.core.query import execute_query
from bgpeek.db import devices as device_crud
from bgpeek.db.pool import _pool as _global_pool  # noqa: F401
from bgpeek.models.device import DeviceCreate
from bgpeek.models.query import QueryRequest, QueryType

_RAW_BGP = (
    "8.8.8.0/24 via 10.0.0.1\n"
    "8.8.8.128/25 via 10.0.0.2\n"
    "1.1.1.0/24 via 10.0.0.3\n"
    "2001:db8::/48 via fe80::1\n"
    "2001:db8:1::/49 via fe80::2"
)


async def _seed_device(pool: asyncpg.Pool, name: str = "rt1") -> None:
    await device_crud.create_device(
        pool,
        DeviceCreate(
            name=name,
            address=IPv4Address("10.0.0.1"),
            platform="juniper_junos",
        ),
    )


def _mock_ssh(output: str = _RAW_BGP) -> AsyncMock:
    mock = AsyncMock()
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock(return_value=False)
    mock.send_command = AsyncMock(return_value=output)
    return mock


@pytest.fixture(autouse=True)
def _patch_pool(pool: asyncpg.Pool) -> None:  # noqa: PT004
    import bgpeek.db.pool as pool_mod

    pool_mod._pool = pool


async def test_public_role_filters_specific_prefixes(pool: asyncpg.Pool) -> None:
    await _seed_device(pool)

    with patch("bgpeek.core.query.SSHClient", return_value=_mock_ssh()):
        result = await execute_query(
            QueryRequest(device_name="rt1", query_type=QueryType.BGP_ROUTE, target="8.8.8.0/24"),
            user_role="public",
        )

    assert "8.8.8.0/24" in result.filtered_output
    assert "8.8.8.128/25" not in result.filtered_output
    assert "1.1.1.0/24" in result.filtered_output
    assert "2001:db8::/48" in result.filtered_output
    assert "2001:db8:1::/49" not in result.filtered_output


async def test_none_role_filters_specific_prefixes(pool: asyncpg.Pool) -> None:
    await _seed_device(pool)

    with patch("bgpeek.core.query.SSHClient", return_value=_mock_ssh()):
        result = await execute_query(
            QueryRequest(device_name="rt1", query_type=QueryType.BGP_ROUTE, target="8.8.8.0/24"),
            user_role=None,
        )

    assert "8.8.8.0/24" in result.filtered_output
    assert "8.8.8.128/25" not in result.filtered_output
    assert "2001:db8:1::/49" not in result.filtered_output


async def test_noc_role_sees_all_prefixes(pool: asyncpg.Pool) -> None:
    await _seed_device(pool)

    with patch("bgpeek.core.query.SSHClient", return_value=_mock_ssh()):
        result = await execute_query(
            QueryRequest(device_name="rt1", query_type=QueryType.BGP_ROUTE, target="8.8.8.0/24"),
            user_role="noc",
        )

    assert "8.8.8.0/24" in result.filtered_output
    assert "8.8.8.128/25" in result.filtered_output
    assert "1.1.1.0/24" in result.filtered_output
    assert "2001:db8::/48" in result.filtered_output
    assert "2001:db8:1::/49" in result.filtered_output
    assert result.filtered_output == result.raw_output


async def test_admin_role_sees_all_prefixes(pool: asyncpg.Pool) -> None:
    await _seed_device(pool)

    with patch("bgpeek.core.query.SSHClient", return_value=_mock_ssh()):
        result = await execute_query(
            QueryRequest(device_name="rt1", query_type=QueryType.BGP_ROUTE, target="8.8.8.0/24"),
            user_role="admin",
        )

    assert "8.8.8.0/24" in result.filtered_output
    assert "8.8.8.128/25" in result.filtered_output
    assert "2001:db8:1::/49" in result.filtered_output
    assert result.filtered_output == result.raw_output


async def test_unknown_role_filters_like_public(pool: asyncpg.Pool) -> None:
    await _seed_device(pool)

    with patch("bgpeek.core.query.SSHClient", return_value=_mock_ssh()):
        result = await execute_query(
            QueryRequest(device_name="rt1", query_type=QueryType.BGP_ROUTE, target="8.8.8.0/24"),
            user_role="unknown_role",
        )

    assert "8.8.8.128/25" not in result.filtered_output
    assert "2001:db8:1::/49" not in result.filtered_output


async def test_privileged_role_ping_unchanged(pool: asyncpg.Pool) -> None:
    await _seed_device(pool)
    raw = "PING 8.8.8.8: 5 packets\n8.8.8.128/25 in output"

    with patch("bgpeek.core.query.SSHClient", return_value=_mock_ssh(raw)):
        result = await execute_query(
            QueryRequest(device_name="rt1", query_type=QueryType.PING, target="8.8.8.8"),
            user_role="noc",
        )

    assert result.filtered_output == raw
