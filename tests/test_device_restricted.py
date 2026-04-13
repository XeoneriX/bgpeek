"""Tests for device access control (restricted flag filtering)."""

from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import IPv4Address
from unittest.mock import AsyncMock

import asyncpg

from bgpeek.db.devices import list_devices

_NOW = datetime.now(tz=UTC)


def _device_row(
    *,
    id: int = 1,
    name: str = "rt1",
    restricted: bool = False,
    enabled: bool = True,
) -> dict:
    return {
        "id": id,
        "name": name,
        "address": IPv4Address("10.0.0.1"),
        "port": 22,
        "platform": "juniper_junos",
        "description": None,
        "location": None,
        "enabled": enabled,
        "restricted": restricted,
        "created_at": _NOW,
        "updated_at": _NOW,
    }


async def test_list_devices_excludes_restricted() -> None:
    pool = AsyncMock(spec=asyncpg.Pool)
    pool.fetch = AsyncMock(return_value=[_device_row(name="public-rt")])
    devices = await list_devices(pool, include_restricted=False)
    query = pool.fetch.call_args[0][0]
    assert "NOT restricted" in query
    assert len(devices) == 1
    assert devices[0].name == "public-rt"


async def test_list_devices_includes_restricted() -> None:
    pool = AsyncMock(spec=asyncpg.Pool)
    pool.fetch = AsyncMock(
        return_value=[
            _device_row(id=1, name="public-rt"),
            _device_row(id=2, name="secret-rt", restricted=True),
        ]
    )
    devices = await list_devices(pool, include_restricted=True)
    query = pool.fetch.call_args[0][0]
    assert "NOT restricted" not in query
    assert len(devices) == 2


async def test_list_devices_enabled_only_and_not_restricted() -> None:
    pool = AsyncMock(spec=asyncpg.Pool)
    pool.fetch = AsyncMock(return_value=[])
    await list_devices(pool, enabled_only=True, include_restricted=False)
    query = pool.fetch.call_args[0][0]
    assert "enabled IS TRUE" in query
    assert "NOT restricted" in query


async def test_list_devices_no_filters() -> None:
    pool = AsyncMock(spec=asyncpg.Pool)
    pool.fetch = AsyncMock(return_value=[_device_row()])
    await list_devices(pool)
    query = pool.fetch.call_args[0][0]
    assert "WHERE" not in query
