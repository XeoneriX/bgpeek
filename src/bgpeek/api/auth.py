"""HTTP handlers for /api/auth and /api/users."""

from __future__ import annotations

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status

from bgpeek.core.auth import require_api_key, require_role
from bgpeek.db import users as crud
from bgpeek.db.pool import get_pool
from bgpeek.models.user import User, UserCreate, UserRole

router = APIRouter(tags=["auth"])


@router.get("/api/auth/me", response_model=User)
async def whoami(user: User = Depends(require_api_key)) -> User:  # noqa: B008
    """Return the authenticated user."""
    return user


_admin = require_role(UserRole.ADMIN)


@router.post("/api/users", response_model=User, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreate,
    _caller: User = Depends(_admin),  # noqa: B008
) -> User:
    """Create a new API-key user (admin only)."""
    try:
        return await crud.create_user(get_pool(), payload)
    except asyncpg.UniqueViolationError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"user with username {payload.username!r} already exists",
        ) from exc


@router.get("/api/users", response_model=list[User])
async def list_users(
    _caller: User = Depends(_admin),  # noqa: B008
) -> list[User]:
    """List all users (admin only)."""
    return await crud.list_users(get_pool())


@router.delete("/api/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    _caller: User = Depends(_admin),  # noqa: B008
) -> None:
    """Delete a user (admin only)."""
    deleted = await crud.delete_user(get_pool(), user_id)
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="user not found")
