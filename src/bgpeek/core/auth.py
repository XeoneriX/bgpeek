"""Authentication dependencies for FastAPI (API key + JWT)."""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Any

import jwt as pyjwt
from fastapi import Depends, Header, HTTPException, status

from bgpeek.core.jwt import decode_token
from bgpeek.db import users as user_crud
from bgpeek.db.pool import get_pool
from bgpeek.models.user import User, UserRole


async def _resolve_bearer(authorization: str) -> User | None:
    """Decode a Bearer token and look up the user."""
    if not authorization.lower().startswith("bearer "):
        return None
    token = authorization[7:]
    try:
        payload = decode_token(token)
    except pyjwt.InvalidTokenError:
        raise HTTPException(  # noqa: B904
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or expired JWT token",
        )
    user_id = int(str(payload["sub"]))
    user = await user_crud.get_user_by_id(get_pool(), user_id)
    if user is None or not user.enabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="user not found or disabled",
        )
    return user


# ---------------------------------------------------------------------------
# Unified dependencies
# ---------------------------------------------------------------------------


async def authenticate(
    x_api_key: str | None = Header(default=None),  # noqa: B008
    authorization: str | None = Header(default=None),  # noqa: B008
) -> User:
    """Resolve either ``X-API-Key`` or ``Authorization: Bearer <jwt>`` to a User, or 401."""
    # 1. Try API key
    if x_api_key is not None:
        user = await user_crud.get_user_by_api_key(get_pool(), x_api_key)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid or disabled API key",
            )
        return user

    # 2. Try Bearer JWT
    if authorization is not None:
        user = await _resolve_bearer(authorization)
        if user is not None:
            return user

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="missing credentials — provide X-API-Key or Authorization header",
    )


async def optional_auth(
    x_api_key: str | None = Header(default=None),  # noqa: B008
    authorization: str | None = Header(default=None),  # noqa: B008
) -> User | None:
    """Like ``authenticate`` but returns None when no credentials are provided."""
    if x_api_key is not None:
        user = await user_crud.get_user_by_api_key(get_pool(), x_api_key)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid or disabled API key",
            )
        return user

    if authorization is not None:
        user = await _resolve_bearer(authorization)
        if user is not None:
            return user

    return None


# ---------------------------------------------------------------------------
# Legacy aliases — kept so existing imports and tests keep working.
# ---------------------------------------------------------------------------

require_api_key = authenticate
optional_api_key = optional_auth


def require_role(
    *roles: UserRole,
) -> Callable[..., Coroutine[Any, Any, User]]:
    """Factory: return a dependency that requires one of the given roles."""

    async def _check(user: User = Depends(authenticate)) -> User:  # noqa: B008
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"role {user.role!r} not in {[r.value for r in roles]}",
            )
        return user

    return _check
