"""HTTP handlers for /api/devices."""

from __future__ import annotations

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status

from bgpeek.core.auth import authenticate, require_role
from bgpeek.core.cache import invalidate_device
from bgpeek.db import devices as crud
from bgpeek.db.pool import get_pool
from bgpeek.models.device import Device, DeviceCreate, DeviceUpdate
from bgpeek.models.user import User, UserRole

router = APIRouter(prefix="/api/devices", tags=["devices"])

_admin = require_role(UserRole.ADMIN)


@router.get("", response_model=list[Device])
async def list_devices(
    enabled_only: bool = False,
    _caller: User = Depends(authenticate),  # noqa: B008
) -> list[Device]:
    """List all devices, optionally filtered to enabled only."""
    return await crud.list_devices(get_pool(), enabled_only=enabled_only)


@router.get("/{device_id}", response_model=Device)
async def get_device(
    device_id: int,
    _caller: User = Depends(authenticate),  # noqa: B008
) -> Device:
    """Get a single device by id."""
    device = await crud.get_device_by_id(get_pool(), device_id)
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="device not found")
    return device


@router.post("", response_model=Device, status_code=status.HTTP_201_CREATED)
async def create_device(
    payload: DeviceCreate,
    _caller: User = Depends(_admin),  # noqa: B008
) -> Device:
    """Create a new device."""
    try:
        return await crud.create_device(get_pool(), payload)
    except asyncpg.UniqueViolationError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail=f"device with name {payload.name!r} already exists"
        ) from exc


@router.patch("/{device_id}", response_model=Device)
async def update_device(
    device_id: int,
    payload: DeviceUpdate,
    _caller: User = Depends(_admin),  # noqa: B008
) -> Device:
    """Partially update a device."""
    device = await crud.update_device(get_pool(), device_id, payload)
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="device not found")
    await invalidate_device(device.name)
    return device


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(
    device_id: int,
    _caller: User = Depends(_admin),  # noqa: B008
) -> None:
    """Delete a device by id."""
    # Look up the device name before deletion for cache invalidation.
    device = await crud.get_device_by_id(get_pool(), device_id)
    deleted = await crud.delete_device(get_pool(), device_id)
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="device not found")
    if device is not None:
        await invalidate_device(device.name)
