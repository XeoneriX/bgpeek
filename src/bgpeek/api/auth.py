"""HTTP handlers for /api/auth and /api/users."""

from __future__ import annotations

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status

from bgpeek.config import settings
from bgpeek.core.auth import authenticate, require_role
from bgpeek.core.jwt import create_token
from bgpeek.core.ldap import authenticate_ldap
from bgpeek.db import users as crud
from bgpeek.db.pool import get_pool
from bgpeek.models.user import (
    LoginRequest,
    LoginResponse,
    User,
    UserCreate,
    UserCreateLocal,
    UserRole,
)

router = APIRouter(tags=["auth"])


@router.get("/api/auth/me", response_model=User)
async def whoami(user: User = Depends(authenticate)) -> User:  # noqa: B008
    """Return the authenticated user."""
    return user


@router.post("/api/auth/login", response_model=LoginResponse)
async def login(body: LoginRequest) -> LoginResponse:
    """Authenticate with username/password and receive a JWT token.

    Auth chain: local DB → LDAP (if enabled). LDAP users are auto-provisioned.
    """
    # 1. Try local DB first
    user = await crud.get_user_by_credentials(get_pool(), body.username, body.password)

    # 2. Fallback to LDAP
    if user is None:
        ldap_info = await authenticate_ldap(body.username, body.password)
        if ldap_info is not None:
            user = await crud.upsert_ldap_user(
                get_pool(),
                username=ldap_info.username,
                email=ldap_info.email,
                role=ldap_info.role,
            )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid username or password",
        )

    # Update last_login_at
    await get_pool().execute(
        "UPDATE users SET last_login_at = now() WHERE id = $1",
        user.id,
    )

    token = create_token(user.id, user.username, user.role.value)
    return LoginResponse(
        token=token,
        token_type="bearer",  # noqa: S106
        expires_in=settings.jwt_expire_minutes * 60,
        user=user,
    )


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


@router.post("/api/users/local", response_model=User, status_code=status.HTTP_201_CREATED)
async def create_local_user(
    payload: UserCreateLocal,
    _caller: User = Depends(_admin),  # noqa: B008
) -> User:
    """Create a new local (password) user (admin only)."""
    try:
        return await crud.create_local_user(get_pool(), payload)
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
