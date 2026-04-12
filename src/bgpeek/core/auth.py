"""API key authentication dependencies for FastAPI."""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import Depends, Header, HTTPException, status

from bgpeek.db import users as user_crud
from bgpeek.db.pool import get_pool
from bgpeek.models.user import User, UserRole


async def require_api_key(
    x_api_key: str = Header(),  # noqa: B008
) -> User:
    """Dependency: resolve `X-API-Key` header to a User or 401."""
    user = await user_crud.get_user_by_api_key(get_pool(), x_api_key)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or disabled API key",
        )
    return user


async def optional_api_key(
    x_api_key: str | None = Header(default=None),  # noqa: B008
) -> User | None:
    """Dependency: resolve `X-API-Key` header to a User, or None for anonymous access."""
    if x_api_key is None:
        return None
    user = await user_crud.get_user_by_api_key(get_pool(), x_api_key)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or disabled API key",
        )
    return user


def require_role(
    *roles: UserRole,
) -> Callable[..., Coroutine[Any, Any, User]]:
    """Factory: return a dependency that requires one of the given roles."""

    async def _check(user: User = Depends(require_api_key)) -> User:  # noqa: B008
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"role {user.role!r} not in {[r.value for r in roles]}",
            )
        return user

    return _check
