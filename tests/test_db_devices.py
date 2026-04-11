"""CRUD tests for bgpeek.db.devices against a real PostgreSQL container."""

from __future__ import annotations

from ipaddress import IPv4Address

import asyncpg
import pytest

from bgpeek.db import devices as crud
from bgpeek.models.device import DeviceCreate, DeviceUpdate


def _payload(name: str = "rt1", **overrides: object) -> DeviceCreate:
    base: dict[str, object] = {
        "name": name,
        "address": IPv4Address("10.0.0.1"),
        "port": 22,
        "platform": "juniper_junos",
        "description": "edge router",
        "location": "M9 cage",
        "enabled": True,
    }
    base.update(overrides)
    return DeviceCreate(**base)  # type: ignore[arg-type]


async def test_list_devices_empty(pool: asyncpg.Pool) -> None:
    assert await crud.list_devices(pool) == []


async def test_create_and_get_by_id(pool: asyncpg.Pool) -> None:
    created = await crud.create_device(pool, _payload())
    assert created.id > 0
    assert created.name == "rt1"
    assert created.address == IPv4Address("10.0.0.1")
    assert created.platform == "juniper_junos"
    assert created.created_at == created.updated_at

    fetched = await crud.get_device_by_id(pool, created.id)
    assert fetched is not None
    assert fetched.id == created.id


async def test_get_by_name(pool: asyncpg.Pool) -> None:
    await crud.create_device(pool, _payload("rt2"))
    fetched = await crud.get_device_by_name(pool, "rt2")
    assert fetched is not None
    assert fetched.name == "rt2"


async def test_get_missing_returns_none(pool: asyncpg.Pool) -> None:
    assert await crud.get_device_by_id(pool, 9999) is None
    assert await crud.get_device_by_name(pool, "nope") is None


async def test_list_devices_orders_by_name(pool: asyncpg.Pool) -> None:
    for name in ("rt-z", "rt-a", "rt-m"):
        await crud.create_device(pool, _payload(name))
    devices = await crud.list_devices(pool)
    assert [d.name for d in devices] == ["rt-a", "rt-m", "rt-z"]


async def test_list_devices_enabled_only(pool: asyncpg.Pool) -> None:
    await crud.create_device(pool, _payload("rt-on", enabled=True))
    await crud.create_device(pool, _payload("rt-off", enabled=False))
    enabled = await crud.list_devices(pool, enabled_only=True)
    assert [d.name for d in enabled] == ["rt-on"]


async def test_create_duplicate_name_raises(pool: asyncpg.Pool) -> None:
    await crud.create_device(pool, _payload("dup"))
    with pytest.raises(asyncpg.UniqueViolationError):
        await crud.create_device(pool, _payload("dup"))


async def test_update_partial(pool: asyncpg.Pool) -> None:
    created = await crud.create_device(pool, _payload())
    updated = await crud.update_device(
        pool, created.id, DeviceUpdate(description="updated", enabled=False)
    )
    assert updated is not None
    assert updated.description == "updated"
    assert updated.enabled is False
    assert updated.name == created.name
    assert updated.updated_at >= created.updated_at


async def test_update_empty_payload_returns_unchanged(pool: asyncpg.Pool) -> None:
    created = await crud.create_device(pool, _payload())
    unchanged = await crud.update_device(pool, created.id, DeviceUpdate())
    assert unchanged is not None
    assert unchanged.id == created.id
    assert unchanged.description == created.description


async def test_update_missing_returns_none(pool: asyncpg.Pool) -> None:
    assert await crud.update_device(pool, 9999, DeviceUpdate(enabled=False)) is None


async def test_delete(pool: asyncpg.Pool) -> None:
    created = await crud.create_device(pool, _payload())
    assert await crud.delete_device(pool, created.id) is True
    assert await crud.get_device_by_id(pool, created.id) is None


async def test_delete_missing_returns_false(pool: asyncpg.Pool) -> None:
    assert await crud.delete_device(pool, 9999) is False
