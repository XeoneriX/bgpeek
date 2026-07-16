"""HTTP handlers for /api/credentials."""

from __future__ import annotations

from pathlib import Path

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query, status

from bgpeek.config import settings
from bgpeek.core.auth import require_role, scoped_endpoint
from bgpeek.core.ssh import SSHClient, SSHError
from bgpeek.db import credentials as crud
from bgpeek.db import devices as device_crud
from bgpeek.db.pool import get_pool
from bgpeek.models.credential import (
    Credential,
    CredentialCreate,
    CredentialUpdate,
    CredentialWithUsage,
)
from bgpeek.models.user import User, UserRole

router = APIRouter(prefix="/api/credentials", tags=["credentials"])
_admin = require_role(UserRole.ADMIN)


@router.get("", response_model=list[CredentialWithUsage])
@scoped_endpoint("credentials:read")
async def list_credentials(
    _caller: User = Depends(_admin),  # noqa: B008
) -> list[CredentialWithUsage]:
    """List all credentials with device count."""
    return await crud.list_credentials(get_pool())


@router.get("/{credential_id}", response_model=Credential)
@scoped_endpoint("credentials:read")
async def get_credential(
    credential_id: int,
    _caller: User = Depends(_admin),  # noqa: B008
) -> Credential:
    """Get a single credential by id."""
    cred = await crud.get_credential(get_pool(), credential_id)
    if cred is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="credential not found")
    return cred


@router.post("", response_model=Credential, status_code=status.HTTP_201_CREATED)
@scoped_endpoint("credentials:create")
async def create_credential(
    payload: CredentialCreate,
    _caller: User = Depends(_admin),  # noqa: B008
) -> Credential:
    """Create a new credential.

    Validates that key_name is provided when auth_type includes ``key``
    and that password is provided when auth_type includes ``password``.
    """
    if "key" in payload.auth_type and not payload.key_name:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="key_name is required when auth_type includes 'key'",
        )
    if "password" in payload.auth_type and not payload.password:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="password is required when auth_type includes 'password'",
        )

    try:
        return await crud.create_credential(get_pool(), payload)
    except asyncpg.UniqueViolationError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"credential with name {payload.name!r} already exists",
        ) from exc


@router.patch("/{credential_id}", response_model=Credential)
@scoped_endpoint("credentials:update")
async def update_credential(
    credential_id: int,
    payload: CredentialUpdate,
    _caller: User = Depends(_admin),  # noqa: B008
) -> Credential:
    """Partially update a credential."""
    cred = await crud.update_credential(get_pool(), credential_id, payload)
    if cred is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="credential not found")
    return cred


@router.delete("/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
@scoped_endpoint("credentials:delete")
async def delete_credential(
    credential_id: int,
    _caller: User = Depends(_admin),  # noqa: B008
) -> None:
    """Delete a credential. Fails with 409 if devices still reference it."""
    try:
        deleted = await crud.delete_credential(get_pool(), credential_id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="credential not found")


@router.post("/{credential_id}/test")
@scoped_endpoint("credentials:read")
async def test_credential(
    credential_id: int,
    device_id: int = Query(..., description="Device to test SSH connectivity against"),  # noqa: B008, PT028
    _caller: User = Depends(_admin),  # noqa: B008, PT019, PT028
) -> dict[str, object]:
    """Test SSH connectivity using this credential against a specific device."""
    # Fetch credential with decrypted password (internal use only).
    raw_cred = await crud.get_credential_raw(get_pool(), credential_id)
    if raw_cred is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="credential not found")

    device = await device_crud.get_device_by_id(get_pool(), device_id)
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="device not found")

    # Resolve SSH key path.
    key_path: Path | None = None
    if raw_cred.key_name:
        key_path = settings.keys_dir / raw_cred.key_name
        if not key_path.is_file():
            return {"success": False, "message": f"key file not found: {raw_cred.key_name}"}

    # Ensure we have at least one auth method for the SSH client.
    password = raw_cred.password if raw_cred.password and raw_cred.password != "****" else None  # noqa: S105
    if password is None and key_path is None:
        return {"success": False, "message": "credential has no usable password or key"}

    client = SSHClient(
        host=str(device.address),
        username=raw_cred.username,
        platform=device.platform,
        port=device.port,
        password=password,
        key_path=key_path,
        timeout=settings.ssh_timeout,
    )

    try:
        await client.connect()
        await client.disconnect()
    except SSHError as exc:
        return {"success": False, "message": str(exc)}

    return {"success": True, "message": "SSH connection successful"}
