"""HTTP handlers for /api/devices."""

from __future__ import annotations

import asyncpg
from fastapi import APIRouter, HTTPException, status

from bgpeek.db import devices as crud
from bgpeek.db.pool import get_pool
from bgpeek.models.device import Device, DeviceCreate, DeviceUpdate

router = APIRouter(prefix="/api/devices", tags=["devices"])


@router.get("", response_model=list[Device])
async def list_devices(enabled_only: bool = False) -> list[Device]:
    """List all devices, optionally filtered to enabled only."""
    return await crud.list_devices(get_pool(), enabled_only=enabled_only)


@router.get("/{device_id}", response_model=Device)
async def get_device(device_id: int) -> Device:
    """Get a single device by id."""
    device = await crud.get_device_by_id(get_pool(), device_id)
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="device not found")
    return device


@router.post("", response_model=Device, status_code=status.HTTP_201_CREATED)
async def create_device(payload: DeviceCreate) -> Device:
    """Create a new device."""
    try:
        return await crud.create_device(get_pool(), payload)
    except asyncpg.UniqueViolationError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail=f"device with name {payload.name!r} already exists"
        ) from exc


@router.patch("/{device_id}", response_model=Device)
async def update_device(device_id: int, payload: DeviceUpdate) -> Device:
    """Partially update a device."""
    device = await crud.update_device(get_pool(), device_id, payload)
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="device not found")
    return device


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(device_id: int) -> None:
    """Delete a device by id."""
    deleted = await crud.delete_device(get_pool(), device_id)
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="device not found")
