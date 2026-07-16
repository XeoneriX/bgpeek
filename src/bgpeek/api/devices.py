"""HTTP handlers for /api/devices."""

from __future__ import annotations

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Request, status

from bgpeek.core.audit_helpers import request_ctx, user_ctx
from bgpeek.core.auth import require_role, scope_gate, scoped_endpoint
from bgpeek.core.cache import invalidate_device
from bgpeek.db import devices as crud
from bgpeek.db.audit import log_audit
from bgpeek.db.pool import get_pool
from bgpeek.models.audit import AuditAction, AuditEntryCreate
from bgpeek.models.device import Device, DeviceCreate, DeviceUpdate
from bgpeek.models.user import User, UserRole
from bgpeek.models.webhook import WebhookEvent

router = APIRouter(prefix="/api/devices", tags=["devices"])

_admin = require_role(UserRole.ADMIN)


@router.get("", response_model=list[Device])
@scoped_endpoint("devices:read")
async def list_devices(
    enabled_only: bool = False,
    _caller: User = Depends(scope_gate),  # noqa: B008
) -> list[Device]:
    """List all devices, optionally filtered to enabled only."""
    include_restricted = _caller.role in (UserRole.ADMIN, UserRole.NOC)
    return await crud.list_devices(
        get_pool(), enabled_only=enabled_only, include_restricted=include_restricted
    )


@router.get("/{device_id}", response_model=Device)
@scoped_endpoint("devices:read")
async def get_device(
    device_id: int,
    _caller: User = Depends(scope_gate),  # noqa: B008
) -> Device:
    """Get a single device by id."""
    device = await crud.get_device_by_id(get_pool(), device_id)
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="device not found")
    return device


@router.post("", response_model=Device, status_code=status.HTTP_201_CREATED)
@scoped_endpoint("devices:create")
async def create_device(
    payload: DeviceCreate,
    request: Request,
    caller: User = Depends(_admin),  # noqa: B008
) -> Device:
    """Create a new device."""
    try:
        device = await crud.create_device(get_pool(), payload)
    except asyncpg.UniqueViolationError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail=f"device with name {payload.name!r} already exists"
        ) from exc

    await log_audit(
        get_pool(),
        AuditEntryCreate(
            action=AuditAction.CREATE_DEVICE,
            success=True,
            device_id=device.id,
            device_name=device.name,
            **user_ctx(caller),
            **request_ctx(request),
        ),
    )

    from bgpeek.core.webhooks import dispatch_webhook

    await dispatch_webhook(
        WebhookEvent.DEVICE_CREATE,
        {"device_id": device.id, "device_name": device.name},
    )
    return device


@router.patch("/{device_id}", response_model=Device)
@scoped_endpoint("devices:update")
async def update_device(
    device_id: int,
    payload: DeviceUpdate,
    request: Request,
    caller: User = Depends(_admin),  # noqa: B008
) -> Device:
    """Partially update a device."""
    device = await crud.update_device(get_pool(), device_id, payload)
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="device not found")
    await invalidate_device(device.name)

    await log_audit(
        get_pool(),
        AuditEntryCreate(
            action=AuditAction.UPDATE_DEVICE,
            success=True,
            device_id=device.id,
            device_name=device.name,
            **user_ctx(caller),
            **request_ctx(request),
        ),
    )

    from bgpeek.core.webhooks import dispatch_webhook

    await dispatch_webhook(
        WebhookEvent.DEVICE_UPDATE,
        {"device_id": device.id, "device_name": device.name},
    )
    return device


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
@scoped_endpoint("devices:delete")
async def delete_device(
    device_id: int,
    request: Request,
    caller: User = Depends(_admin),  # noqa: B008
) -> None:
    """Delete a device by id."""
    # Look up the device name before deletion for cache invalidation + audit.
    device = await crud.get_device_by_id(get_pool(), device_id)
    deleted = await crud.delete_device(get_pool(), device_id)
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="device not found")
    if device is not None:
        await invalidate_device(device.name)

    await log_audit(
        get_pool(),
        AuditEntryCreate(
            action=AuditAction.DELETE_DEVICE,
            success=True,
            # device_id is intentionally NULL: the row was just deleted, so
            # the FK to devices(id) would violate on INSERT. device_name
            # preserves the context for the audit reader.
            device_id=None,
            device_name=device.name if device else None,
            **user_ctx(caller),
            **request_ctx(request),
        ),
    )

    from bgpeek.core.webhooks import dispatch_webhook

    await dispatch_webhook(
        WebhookEvent.DEVICE_DELETE,
        {"device_id": device_id, "device_name": device.name if device else None},
    )
